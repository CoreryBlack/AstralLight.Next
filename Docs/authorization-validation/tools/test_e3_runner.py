#!/usr/bin/env python3
"""Offline unit tests for tools/e3_runner.py.

Every test uses in-memory fakes only: no database, Redis, HTTP service,
network, container, or migration is touched. The suite verifies:

- import safety (importing the module performs no I/O and creates no files),
- config validation (cards distinct, hard bounds on interval/windows/attempt
  count, isolated-fixture flag, node list bounds),
- plan mode (PLANNED, stable operation ids, marker contract, checksums),
- the live gate: no probe/controller call happens without explicit
  ``allow_live_execution`` + external approval + isolated fixture, and the
  real platform primitives stay BLOCKED (nothing ships in the module),
- marker ordering (wall + monotonic, completeness, operation-id pairing),
- controller failure recovery: at most one dispatch per phase, no blind
  retry, no cleanup, UNKNOWN + manual reconciliation prompt, and
  injection/drain-may-still-be-active flags,
- actor switching: every decision sample carries its role card through the
  actor-aware probe; a probe without ``signed_get_for_role`` is BLOCKED,
- durable per-attempt terminal reconciliation (PASS only with durable rows),
  missing logs (BLOCKED), unknown ACK (UNKNOWN), and the attempt bound,
- per-category SKIP/UNKNOWN behavior for the four output categories,
- probe-level decision vs host admission: request ids retained, ALLOW
  confirmed by the request-side cross-check, contradictions are FAIL,
- no sensitive deployment constants and scrubbed host-like output.
"""

from __future__ import annotations

import contextlib
import copy
import io
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, _HERE)

import e3_runner  # noqa: E402
import experiment_common  # noqa: E402
from e3_e4 import E3SampleConfig  # noqa: E402

UTC_EPOCH_NS = int(datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1e9)
RUN_ID = "authz-validation-e3-test"
APPROVAL_REF = "approval-e3-0001"

BASE_CONFIG: Dict[str, Any] = {
    "run_id": RUN_ID,
    "e3": {
        "allowlist": {
            "target_card": "card-target-1",
            "unrelated_card": "card-unrelated-1",
            "cold_card": "card-cold-1",
            "isolated_fixture": True,
        },
        "windows": {
            "sampling_interval_s": 0.02,
            "injection_window_s": 0.05,
            "drain_window_s": 0.05,
        },
        "bounds": {"max_attempts": 8},
        "nodes": ["node-a"],
        "decision_node": "gateway",
    },
}

ROW_QUERIES = (
    "SELECT COUNT(*) FROM authorization_delta_event",
    "SELECT COUNT(*) FROM authorization_projection_current",
    "SELECT COUNT(*) FROM authorization_archive_outbox",
)
CACHE_EPOCH_KEY = "astral:auth:cache_epoch"

WALL_BASE_NS = 1_780_000_000_000_000_000


def e3_line(
    event: str,
    sequence: int,
    *,
    delta: int = 101,
    event_id: str = "evt-1",
    operation_id: str = "op-e3-1",
    attempts: Optional[int] = None,
    durable: Optional[bool] = None,
    outcome: Optional[str] = None,
    process: str = "worker-1",
) -> str:
    """One valid E3 projector observation log line (fake fixture)."""
    record: Dict[str, Any] = {
        "message": "e3 projector observation",
        "event": event,
        "process_observation_id": process,
        "event_sequence": sequence,
        "wall_unix_ns": WALL_BASE_NS + sequence,
        "delta_event_id": delta,
        "event_id": event_id,
        "operation_id": operation_id,
    }
    if attempts is not None:
        record["attempts"] = attempts
    if durable is not None:
        record["durable"] = durable
    if outcome is not None:
        record["outcome"] = outcome
    return json.dumps(record)


PUBLISH_HISTORY: List[str] = [
    e3_line("claim_committed", 1, attempts=1),
    e3_line("publish_committed", 2, attempts=1, durable=True, outcome="succeeded"),
]
BACKOFF_PENDING_HISTORY: List[str] = [
    e3_line("claim_committed", 1, attempts=1),
    e3_line("backoff_committed", 2, attempts=1, durable=True, outcome="retry_scheduled"),
    e3_line("claim_committed", 3, attempts=2),
    e3_line("backoff_committed", 4, attempts=2, durable=True, outcome="retry_scheduled"),
]
BOUND_EXCEEDED_HISTORY: List[str] = [
    e3_line("claim_committed", 1, attempts=1),
    e3_line("backoff_committed", 2, attempts=1, durable=True, outcome="retry_scheduled"),
    e3_line("claim_committed", 3, attempts=2),
    e3_line("publish_committed", 4, attempts=2, durable=True, outcome="succeeded"),
]
UNKNOWN_ACK_HISTORY: List[str] = [
    e3_line("claim_committed", 1, attempts=1),
    e3_line("terminal_unknown", 2, attempts=1, durable=True, outcome="ack_unknown"),
]
TWO_DELTA_HISTORY: List[str] = PUBLISH_HISTORY + [
    e3_line("claim_committed", 10, delta=202, event_id="evt-2", attempts=1),
    e3_line(
        "publish_committed",
        11,
        delta=202,
        event_id="evt-2",
        attempts=1,
        durable=True,
        outcome="succeeded",
    ),
]

PUBLISH_ROWS: Dict[str, Dict[str, Any]] = {"evt-1": {"attempts": 1, "status": "SUCCEEDED"}}
BACKOFF_ROWS: Dict[str, Dict[str, Any]] = {"evt-1": {"attempts": 2, "status": "PENDING"}}
UNKNOWN_ACK_ROWS: Dict[str, Dict[str, Any]] = {"evt-1": {"attempts": 1, "status": "UNKNOWN"}}
TWO_DELTA_ROWS: Dict[str, Dict[str, Any]] = {
    "evt-1": {"attempts": 1, "status": "SUCCEEDED"},
    "evt-2": {"attempts": 1, "status": "SUCCEEDED"},
}


def approval_record(run_id: str = RUN_ID, ref: str = APPROVAL_REF) -> Dict[str, Any]:
    return {"run_id": run_id, "approval_ref": ref, "approved_by": "test-approver"}


def counter_clock(start: int, step: int) -> Any:
    state = {"value": start}

    def _next() -> int:
        value = state["value"]
        state["value"] += step
        return value

    return _next


class FakeE3Probe:
    """In-memory actor-aware read-only probe (e3_e4 contract)."""

    def __init__(
        self,
        *,
        decision_fn: Optional[Any] = None,
        sql_error: Optional[Exception] = None,
        redis_error: Optional[Exception] = None,
        clock: float = UTC_EPOCH_NS / 1e9,
    ) -> None:
        self.decision_fn = decision_fn
        self.sql_error = sql_error
        self.redis_error = redis_error
        self.clock_value = clock
        self.role_calls: List[Tuple[str, str, str, str]] = []
        self.sql_calls: List[str] = []
        self.redis_calls: List[Tuple[str, ...]] = []
        self.decision_by_request: Dict[str, str] = {}
        self._seq = itertools.count(1)

    def sql(self, query: str) -> List[List[str]]:
        if self.sql_error is not None:
            raise self.sql_error
        self.sql_calls.append(query)
        return [["1"]]

    def redis(self, *argv: str) -> str:
        if self.redis_error is not None:
            raise self.redis_error
        self.redis_calls.append(tuple(argv))
        verb = argv[0] if argv else ""
        if verb == "PING":
            return "PONG"
        if verb == "GET" and len(argv) > 1 and argv[1] == CACHE_EPOCH_KEY:
            return "epoch-token-1"
        return ""

    def signed_get(self, node: str, path: str) -> Tuple[int, Dict[str, Any]]:
        return 200, {"allowed": True}

    def signed_get_for_role(
        self, role: str, card: str, node: str, path: str
    ) -> Tuple[int, Dict[str, Any], str]:
        self.role_calls.append((role, card, node, path))
        if self.decision_fn is not None:
            status, body = self.decision_fn(role, card)
        else:
            status, body = 503, {"reason": "AUTHORIZATION_PENDING"}
        request_id = "req-%04d" % next(self._seq)
        if status == 200 and body.get("allowed") is True:
            self.decision_by_request[request_id] = "ALLOW"
        elif status in (401, 403, 503) or body.get("allowed") is False:
            self.decision_by_request[request_id] = "PENDING" if status == 503 else "DENY"
        else:
            self.decision_by_request[request_id] = "UNKNOWN"
        return status, body, request_id

    def clock_sample(self) -> float:
        return self.clock_value


def default_decisions(role: str, card: str) -> Tuple[int, Dict[str, Any]]:
    if role == "target":
        return 503, {"reason": "AUTHORIZATION_PENDING", "errorType": "AUTHORIZATION_PENDING"}
    if role == "unrelated":
        return 200, {"allowed": True, "reason": "ok", "generation": "g-1"}
    return 200, {"allowed": False, "reason": "NO_MATCH"}


def allow_everywhere(role: str, card: str) -> Tuple[int, Dict[str, Any]]:
    return 200, {"allowed": True, "reason": "ok"}


def pending_everywhere(role: str, card: str) -> Tuple[int, Dict[str, Any]]:
    return 503, {"reason": "AUTHORIZATION_PENDING"}


class FakeController:
    """In-memory injection controller with optional failure injection."""

    def __init__(self, fail_at: Optional[str] = None) -> None:
        self.calls: List[Tuple[str, str]] = []
        self.fail_at = fail_at

    def _record(self, name: str, operation_id: str) -> None:
        self.calls.append((name, operation_id))
        if self.fail_at == name:
            raise RuntimeError("injected controller failure")

    def begin_injection(self, operation_id: str) -> Mapping[str, Any]:
        self._record("begin_injection", operation_id)
        return {"ack": "injection-active"}

    def end_injection(self, operation_id: str) -> Mapping[str, Any]:
        self._record("end_injection", operation_id)
        return {"ack": "injection-stopped"}

    def begin_drain(self, operation_id: str) -> Mapping[str, Any]:
        self._record("begin_drain", operation_id)
        return {"ack": "drain-started"}

    def end_drain(self, operation_id: str) -> Mapping[str, Any]:
        self._record("end_drain", operation_id)
        return {"ack": "drain-finished"}


class HangingController(FakeController):
    """Simulates a controller phase that never returns (timeout path)."""

    def begin_injection(self, operation_id: str) -> Mapping[str, Any]:
        self.calls.append(("begin_injection", operation_id))
        time.sleep(1.0)
        return {"ack": "never"}


class FakeE3Collector:
    def __init__(self, lines_by_node: Optional[Mapping[str, Sequence[str]]] = None, error: Optional[Exception] = None) -> None:
        self.lines_by_node = dict(lines_by_node or {})
        self.error = error
        self.calls: List[str] = []

    def collect_e3_lines(self, node: str) -> List[str]:
        self.calls.append(node)
        if self.error is not None:
            raise self.error
        return list(self.lines_by_node.get(node, []))


class FakeRowReader:
    def __init__(self, rows: Optional[Mapping[str, Mapping[str, Any]]] = None, error: Optional[Exception] = None) -> None:
        self.rows = dict(rows or {})
        self.error = error
        self.requested: List[List[str]] = []

    def read_delta_rows(self, event_ids: Sequence[str]) -> Mapping[str, Mapping[str, Any]]:
        self.requested.append(list(event_ids))
        if self.error is not None:
            raise self.error
        wanted = set(event_ids)
        return {key: value for key, value in self.rows.items() if key in wanted}


class DynamicRequestLogCollector:
    """Builds consistent (or contradictory) request-side event log lines.

    ``mode``: ``consistent`` (ALLOW ids get host_admission; non-ALLOW ids do
    not), ``deny_all`` (explicit host denial for every id, no admission),
    ``admit_all`` (host_admission for every id), ``empty`` (no lines).
    """

    def __init__(self, probe: Optional[FakeE3Probe] = None, mode: str = "consistent") -> None:
        self.probe = probe
        self.mode = mode
        self.requested: List[List[str]] = []
        self._sequence = itertools.count(1)

    def collect_request_lines(self, node: str, request_ids: Sequence[str]) -> List[str]:
        self.requested.append(list(request_ids))
        if self.mode == "empty":
            return []
        lines: List[str] = []
        for request_id in request_ids:
            classification = (
                self.probe.decision_by_request.get(request_id, "ALLOW")
                if self.probe is not None
                else "ALLOW"
            )
            sequence = next(self._sequence)
            if self.mode == "admit_all" or (self.mode == "consistent" and classification == "ALLOW"):
                lines.append(
                    json.dumps(
                        {
                            "message": "e1 authorization observation",
                            "event": "decision_return",
                            "request_id": request_id,
                            "process_observation_id": "request-worker-1",
                            "event_sequence": sequence,
                            "wall_unix_ns": UTC_EPOCH_NS + sequence,
                            "allowed": True,
                            "reason": "",
                        }
                    )
                )
                lines.append(
                    json.dumps(
                        {
                            "message": "e1 authorization observation",
                            "event": "host_admission",
                            "request_id": request_id,
                            "process_observation_id": "request-worker-1",
                            "event_sequence": next(self._sequence),
                            "wall_unix_ns": UTC_EPOCH_NS + sequence,
                            "allowed": True,
                        }
                    )
                )
            else:
                allowed = False if self.mode == "deny_all" else None
                lines.append(
                    json.dumps(
                        {
                            "message": "e1 authorization observation",
                            "event": "decision_return",
                            "request_id": request_id,
                            "process_observation_id": "request-worker-1",
                            "event_sequence": sequence,
                            "wall_unix_ns": UTC_EPOCH_NS + sequence,
                            "allowed": allowed,
                            "reason": "" if allowed is False else "AUTHORIZATION_PENDING",
                        }
                    )
                )
        return lines


class SqlOnlyProbe:
    """Read-only probe WITHOUT the actor-aware extension (BLOCKED coverage)."""

    def sql(self, query: str) -> List[List[str]]:
        return [["1"]]

    def redis(self, *argv: str) -> str:
        return "PONG" if argv and argv[0] == "PING" else "epoch-token-1"

    def signed_get(self, node: str, path: str) -> Tuple[int, Dict[str, Any]]:
        return 200, {"allowed": True}


def write_config(tmp: Path, config: Optional[Mapping[str, Any]] = None) -> Path:
    path = tmp / "e3_config.json"
    path.write_text(json.dumps(config or BASE_CONFIG), encoding="utf-8")
    return path


class E3RunnerTestCase(unittest.TestCase):
    """Shared helpers for campaign-level tests."""

    _UNSET = object()

    def run_campaign(
        self,
        tmp: Path,
        *,
        probe: Any = _UNSET,
        controller: Any = _UNSET,
        collector: Any = None,
        row_reader: Any = None,
        request_log_collector: Any = None,
        sample_config: Optional[E3SampleConfig] = None,
        config: Optional[Mapping[str, Any]] = None,
        allow_live_execution: bool = True,
        approval_ref: Optional[str] = APPROVAL_REF,
        approval_record: Any = None,
        approval_validator: Any = _UNSET,
        wall_clock: Optional[Any] = None,
        mono_clock: Optional[Any] = None,
    ) -> Dict[str, Any]:
        unset = E3RunnerTestCase._UNSET
        resolved_probe = FakeE3Probe(decision_fn=default_decisions) if probe is unset else probe
        resolved_controller = FakeController() if controller is unset else controller
        resolved_approval_validator = (
            (lambda run_id, approval_ref_value, config_hash: (
                run_id == RUN_ID
                and approval_ref_value == APPROVAL_REF
                and len(config_hash) == 64
            ))
            if approval_validator is unset
            else approval_validator
        )
        result = e3_runner.execute_campaign(
            config or BASE_CONFIG,
            tmp / "out",
            probe=resolved_probe,
            controller=resolved_controller,
            collector=collector,
            row_reader=row_reader,
            request_log_collector=request_log_collector,
            sample_config=sample_config,
            allow_live_execution=allow_live_execution,
            approval_ref=approval_ref,
            approval_record=approval_record if approval_record is not None else approval_record_default(),
            approval_validator=resolved_approval_validator,
            wall_clock=wall_clock,
            mono_clock=mono_clock,
        )
        return result

    def assertNoPass(self, result: Mapping[str, Any]) -> None:
        self.assertNotEqual(result["status"], "PASS")
        self.assertEqual(result["e3_evidence_claim"], e3_runner.E3_CLAIM_NONE)


def approval_record_default() -> Dict[str, Any]:
    return approval_record()


class TestImportSafety(unittest.TestCase):
    def test_import_performs_no_io(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            env = dict(os.environ)
            env["PYTHONPATH"] = str(_HERE) + os.pathsep + env.get("PYTHONPATH", "")
            completed = subprocess.run(
                [sys.executable, "-c", "import e3_runner; print('import-ok')"],
                cwd=str(tmp),
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("import-ok", completed.stdout)
            self.assertEqual(list(tmp.iterdir()), [], "import must not create files")


class TestConfigValidation(unittest.TestCase):
    def test_valid_config_loads(self) -> None:
        settings = e3_runner.load_e3_config(BASE_CONFIG)
        self.assertEqual(settings.run_id, RUN_ID)
        self.assertTrue(settings.isolated_fixture)
        self.assertEqual(
            (settings.target_card, settings.unrelated_card, settings.cold_card),
            ("card-target-1", "card-unrelated-1", "card-cold-1"),
        )

    def test_missing_sections(self) -> None:
        for config, label in (({}, "invalid:run_id"), ({"run_id": RUN_ID}, "missing:e3")):
            with self.assertRaises(e3_runner.ConfigError) as ctx:
                e3_runner.load_e3_config(config)
            self.assertIn(label, ctx.exception.problems)

    def test_cards_must_be_distinct_and_safe(self) -> None:
        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["allowlist"]["unrelated_card"] = "card-target-1"
        with self.assertRaises(e3_runner.ConfigError) as ctx:
            e3_runner.load_e3_config(config)
        self.assertIn("invalid:e3.allowlist.cards_not_distinct", ctx.exception.problems)

        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["allowlist"]["cold_card"] = "bad card"
        with self.assertRaises(e3_runner.ConfigError) as ctx:
            e3_runner.load_e3_config(config)
        self.assertIn("invalid:e3.allowlist.cold_card", ctx.exception.problems)

    def test_isolated_fixture_required_bool(self) -> None:
        config = copy.deepcopy(BASE_CONFIG)
        del config["e3"]["allowlist"]["isolated_fixture"]
        with self.assertRaises(e3_runner.ConfigError) as ctx:
            e3_runner.load_e3_config(config)
        self.assertIn("invalid:e3.allowlist.isolated_fixture", ctx.exception.problems)

    def test_sampling_bounds(self) -> None:
        cases = [
            ("sampling_interval_s", 0.005),
            ("sampling_interval_s", 601.0),
            ("injection_window_s", -1.0),
            ("injection_window_s", 3601.0),
            ("injection_window_s", True),
        ]
        for key, value in cases:
            config = copy.deepcopy(BASE_CONFIG)
            config["e3"]["windows"][key] = value
            with self.assertRaises(e3_runner.ConfigError) as ctx:
                e3_runner.load_e3_config(config)
            self.assertIn("invalid:e3.windows.%s" % key, ctx.exception.problems)

    def test_sample_count_bound(self) -> None:
        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["windows"]["drain_window_s"] = 3600.0
        config["e3"]["windows"]["sampling_interval_s"] = 0.01
        with self.assertRaises(e3_runner.ConfigError) as ctx:
            e3_runner.load_e3_config(config)
        self.assertIn("invalid:e3.windows.drain_window_sample_bound", ctx.exception.problems)

    def test_attempt_count_bound(self) -> None:
        for value in (0, e3_runner.MAX_ATTEMPTS + 1, True, "4"):
            config = copy.deepcopy(BASE_CONFIG)
            config["e3"]["bounds"]["max_attempts"] = value
            with self.assertRaises(e3_runner.ConfigError) as ctx:
                e3_runner.load_e3_config(config)
            self.assertIn("invalid:e3.bounds.max_attempts", ctx.exception.problems)

    def test_nodes_and_decision_node_bounds(self) -> None:
        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["nodes"] = []
        with self.assertRaises(e3_runner.ConfigError) as ctx:
            e3_runner.load_e3_config(config)
        self.assertIn("invalid:e3.nodes", ctx.exception.problems)

        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["nodes"] = ["node-a", "node-a"]
        with self.assertRaises(e3_runner.ConfigError) as ctx:
            e3_runner.load_e3_config(config)
        self.assertIn("invalid:e3.nodes", ctx.exception.problems)

        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["decision_node"] = ""
        with self.assertRaises(e3_runner.ConfigError) as ctx:
            e3_runner.load_e3_config(config)
        self.assertIn("invalid:e3.decision_node", ctx.exception.problems)


class TestPlanMode(unittest.TestCase):
    def test_plan_is_offline_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            out = tmp / "plan_out"
            first = e3_runner.execute_plan(BASE_CONFIG, out)
            second = e3_runner.execute_plan(BASE_CONFIG, tmp / "plan_out2")
            self.assertEqual(first["status"], "PLANNED")
            self.assertEqual(first["mode"], "plan")
            self.assertEqual(first["operationIds"], second["operationIds"])
            self.assertEqual(
                first["operationIds"],
                e3_runner.e3_operation_ids(RUN_ID),
                "operation ids must be stable for the run id",
            )
            for value in first["operationIds"].values():
                self.assertIsNotNone(experiment_common.SAFE_ID.fullmatch(value))
            self.assertEqual(
                first["outputCategories"], list(e3_runner.OUTPUT_CATEGORIES)
            )
            self.assertIn("markerContract", first)
            self.assertEqual(
                first["markerContract"]["timeSources"], ["wall_unix_ns", "monotonic_ns"]
            )
            self.assertEqual(first["livePrimitiveStatus"], "BLOCKED")
            self.assertIn("gateRequirements", first)
            self.assertIn(
                "independent approval_validator(run_id, approval_ref, config_sha256) == True",
                first["gateRequirements"],
            )
            experiment_common.verify_checksums(out, out / "checksums.sha256")


class TestLiveGate(E3RunnerTestCase):
    def setUp(self) -> None:
        self.probe = FakeE3Probe(decision_fn=default_decisions)
        self.controller = FakeController()

    def assertBlockedUntouched(
        self, result: Mapping[str, Any], expected_problem: str
    ) -> None:
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn(expected_problem, result["problems"])
        self.assertEqual(self.controller.calls, [], "controller must never be called")
        self.assertEqual(self.probe.role_calls, [], "probe must never be called")
        self.assertEqual(result["e3_evidence_claim"], e3_runner.E3_CLAIM_NONE)

    def test_live_not_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp),
                probe=self.probe,
                controller=self.controller,
                allow_live_execution=False,
            )
            self.assertBlockedUntouched(result, "live_not_enabled")

    def test_missing_approval_ref(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp),
                probe=self.probe,
                controller=self.controller,
                approval_ref=None,
            )
            self.assertBlockedUntouched(result, "approval_ref_missing_or_unsafe")

    def test_approval_record_run_id_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp),
                probe=self.probe,
                controller=self.controller,
                approval_record=approval_record(run_id="authz-validation-other"),
            )
            self.assertBlockedUntouched(result, "approval_record_run_id_mismatch")

    def test_self_supplied_approval_record_is_insufficient(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp),
                probe=self.probe,
                controller=self.controller,
                approval_validator=None,
            )
            self.assertBlockedUntouched(result, "independent_user_approval_not_verified")

    def test_approval_record_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            record_path = tmp / "approval.json"
            record_path.write_text(json.dumps(approval_record()), encoding="utf-8")
            result = self.run_campaign(
                tmp,
                probe=self.probe,
                controller=self.controller,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(self.probe),
                approval_record=str(record_path),
            )
            self.assertEqual(result["status"], "PASS")

    def test_fixture_not_isolated(self) -> None:
        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["allowlist"]["isolated_fixture"] = False
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp), probe=self.probe, controller=self.controller, config=config
            )
            self.assertBlockedUntouched(result, "fixture_not_isolated")

    def test_missing_probe_and_controller(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(Path(raw_tmp), probe=None, controller=self.controller)
            self.assertBlockedUntouched(result, "missing_probe")
            limitations = {item["item"]: item for item in result["limitations"]}
            self.assertEqual(limitations["real_platform_primitives"]["status"], "BLOCKED")

        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(Path(raw_tmp), probe=self.probe, controller=None)
            self.assertBlockedUntouched(result, "missing_injection_controller")

    def test_cli_live_without_injected_primitives_is_blocked(self) -> None:
        """The CLI can never reach the real platform injection primitive."""
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            config_path = write_config(tmp)
            record_path = tmp / "approval.json"
            record_path.write_text(json.dumps(approval_record()), encoding="utf-8")
            out = tmp / "out"
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = e3_runner.main(
                    [
                        "run",
                        "--config",
                        str(config_path),
                        "--out",
                        str(out),
                        "--live",
                        "--approval-ref",
                        APPROVAL_REF,
                        "--approval-record",
                        str(record_path),
                    ]
                )
            self.assertEqual(code, 1)
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "BLOCKED")
            self.assertIn(
                "independent_user_approval_not_verified", manifest["problems"]
            )


class TestGoldenPath(E3RunnerTestCase):
    def test_full_claim_pass(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            probe = FakeE3Probe(decision_fn=default_decisions)
            controller = FakeController()
            result = self.run_campaign(
                tmp,
                probe=probe,
                controller=controller,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
                wall_clock=counter_clock(UTC_EPOCH_NS, 1_000_000),
                mono_clock=counter_clock(1_000, 10),
            )
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["e3_evidence_claim"], e3_runner.E3_CLAIM_FULL)

            # Complete, ordered marker intervals with wall + monotonic time.
            markers = result["markers"]
            self.assertEqual([marker["marker"] for marker in markers], list(e3_runner.MARKER_NAMES))
            monotonic = [marker["monotonic_ns"] for marker in markers]
            self.assertEqual(monotonic, sorted(monotonic))
            self.assertEqual(len(set(monotonic)), len(monotonic))
            walls = [marker["wall_unix_ns"] for marker in markers]
            self.assertEqual(walls, sorted(walls))
            operation_ids = result["operationIds"]
            self.assertEqual(
                controller.calls,
                [
                    ("begin_injection", operation_ids["injection"]),
                    ("end_injection", operation_ids["injection"]),
                    ("begin_drain", operation_ids["drain"]),
                    ("end_drain", operation_ids["drain"]),
                ],
            )
            self.assertEqual(markers[0]["operation_id"], operation_ids["injection"])
            self.assertEqual(markers[2]["operation_id"], operation_ids["drain"])
            self.assertTrue(markers[0]["ack"]["present"])

            # All four output categories PASS.
            categories = result["outputCategories"]
            self.assertEqual(
                sorted(categories), sorted(e3_runner.OUTPUT_CATEGORIES)
            )
            for name, category in categories.items():
                self.assertEqual(
                    category["status"], "PASS", "%s must PASS on the golden path" % name
                )

            # Durable per-attempt reconciliation.
            per_event = result["perEventRetryHistory"]
            self.assertEqual(per_event["status"], "PASS")
            self.assertEqual(per_event["attempts"], 1)
            self.assertEqual(
                result["attemptTime"]["paired_attempts"],
                1,
                "one claim->terminal pair must be accumulated",
            )

            # Request ids retained; probe-level basis explicit; host confirmed.
            sampling = result["sampling"]
            self.assertGreaterEqual(sampling["injection_window"]["sampleCount"], 1)
            self.assertGreaterEqual(sampling["drain_window"]["sampleCount"], 1)
            self.assertGreaterEqual(sampling["injection_window"]["requestIdCount"], 3)
            for window in ("injection_window", "drain_window"):
                summary = sampling[window]["summary"]
                self.assertTrue(summary["completed"])
                self.assertEqual(summary["e3_evidence_claim"], "NOT_CLAIMED")
            crosscheck = result["hostAdmissionCrosscheck"]
            self.assertEqual(crosscheck["status"], "PASS")
            self.assertGreaterEqual(crosscheck["confirmed"], 1)
            self.assertFalse(result["manual_reconciliation_required"])

            # Decision digests always carry the probe-level basis and request id.
            artifact = json.loads(
                (tmp / "out" / "e3-samples-injection.json").read_text(encoding="utf-8")
            )
            for sample in artifact["samples"]:
                for decision in sample["decisions"]:
                    self.assertEqual(decision["decision_basis"], "probe_level")
                    self.assertTrue(decision["request_id"])
            self.assertTrue(artifact["request_ids"])

            # Evidence artifacts are checksummed.
            experiment_common.verify_checksums(tmp / "out", tmp / "out" / "checksums.sha256")

    def test_actor_switching_roles_and_cards(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            probe = FakeE3Probe(decision_fn=default_decisions)
            self.run_campaign(
                tmp,
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            settings = e3_runner.load_e3_config(BASE_CONFIG)
            expected = {
                ("target", settings.target_card),
                ("unrelated", settings.unrelated_card),
                ("cold", settings.cold_card),
            }
            seen = {(role, card) for role, card, _node, _path in probe.role_calls}
            self.assertEqual(seen, expected)
            for _role, _card, node, path in probe.role_calls:
                self.assertEqual(node, settings.decision_node)
                self.assertIn("cardId=", path)
                self.assertIn("card_id=", path)


class TestMarkerOrdering(E3RunnerTestCase):
    def test_wall_clock_regression_is_unknown(self) -> None:
        state = {"value": UTC_EPOCH_NS + 1_000_000_000}

        def backwards() -> int:
            state["value"] -= 1_000_000
            return state["value"]

        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
                wall_clock=backwards,
            )
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertIn("marker_wall_order_violation", result["problems"])
            self.assertNoPass(result)

    def test_missing_markers_on_abort(self) -> None:
        controller = FakeController(fail_at="end_drain")
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(Path(raw_tmp), controller=controller)
            self.assertEqual(result["status"], "UNKNOWN")
            markers = result["markers"]
            self.assertEqual(
                [marker["marker"] for marker in markers],
                ["injection_start", "injection_end", "drain_start"],
            )
            self.assertIn("markers_missing:drain_end", result["problems"])
            self.assertIn("drain_not_completed", result["problems"])
            self.assertTrue(result["drain_may_still_be_active"])
            self.assertFalse(result["injection_may_still_be_active"])


class TestControllerFailureRecovery(E3RunnerTestCase):
    def test_begin_injection_failure_no_retry(self) -> None:
        controller = FakeController(fail_at="begin_injection")
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            result = self.run_campaign(tmp, controller=controller)
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertEqual(
                controller.calls, [("begin_injection", result["operationIds"]["injection"])]
            )
            self.assertEqual(result["markers"], [])
            self.assertTrue(result["controller_state_unknown"])
            self.assertFalse(result["injection_may_still_be_active"])
            self.assertFalse(result["drain_may_still_be_active"])
            self.assertTrue(result["manual_reconciliation_required"])
            self.assertIn("MANUAL_RECONCILIATION_REQUIRED", result["reconciliation_prompt"])
            self.assertEqual(
                result["sampling"]["injection_window"]["outcome"], "skipped"
            )
            self.assertEqual(result["sampling"]["drain_window"]["outcome"], "skipped")
            self.assertNoPass(result)

    def test_end_injection_failure_leaves_injection_active(self) -> None:
        controller = FakeController(fail_at="end_injection")
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            result = self.run_campaign(tmp, controller=controller)
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertEqual(
                controller.calls,
                [
                    ("begin_injection", result["operationIds"]["injection"]),
                    ("end_injection", result["operationIds"]["injection"]),
                ],
                "each phase is dispatched at most once; no blind retry, no drain",
            )
            self.assertTrue(result["injection_may_still_be_active"])
            self.assertTrue(result["manual_reconciliation_required"])
            self.assertEqual(result["sampling"]["drain_window"]["outcome"], "skipped")
            # The injection-window samples are still retained as evidence.
            self.assertGreaterEqual(result["sampling"]["injection_window"]["sampleCount"], 1)
            self.assertEqual(
                result["perEventRetryHistory"]["status"], "SKIP",
                "per-attempt validation is not reached when the drain never completed",
            )
            self.assertNoPass(result)

    def test_end_drain_failure_leaves_drain_active(self) -> None:
        controller = FakeController(fail_at="end_drain")
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(Path(raw_tmp), controller=controller)
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertTrue(result["drain_may_still_be_active"])
            self.assertEqual(
                result["perEventRetryHistory"]["note"],
                "drain_not_completed_after_abort:end_drain",
            )
            self.assertNoPass(result)

    def test_timeout_stops_without_retry(self) -> None:
        controller = HangingController()
        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["controller_timeout_s"] = 0.05
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(Path(raw_tmp), controller=controller, config=config)
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertEqual(len(controller.calls), 1, "no retry after timeout")
            self.assertIn("controller_phase_failure:begin_injection", result["problems"])
            self.assertEqual(
                [failure["problem"] for failure in result["phaseFailures"]],
                ["timeout:begin_injection"],
            )
            self.assertTrue(result["manual_reconciliation_required"])
            self.assertNoPass(result)


class TestPerEventDurable(E3RunnerTestCase):
    def test_backoff_tail_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": BACKOFF_PENDING_HISTORY}),
                row_reader=FakeRowReader(BACKOFF_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            self.assertEqual(result["perEventRetryHistory"]["status"], "PENDING")
            self.assertEqual(result["status"], "PENDING")
            self.assertNoPass(result)

    def test_missing_durable_row_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader({}),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            per_event = result["perEventRetryHistory"]
            self.assertEqual(per_event["status"], "UNKNOWN")
            self.assertIn("101:missing_durable_row", per_event["unknown"])
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertTrue(result["manual_reconciliation_required"])

    def test_durable_status_mismatch_is_unknown(self) -> None:
        rows = {"evt-1": {"attempts": 1, "status": "QUARANTINED"}}
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(rows),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            self.assertEqual(result["perEventRetryHistory"]["status"], "UNKNOWN")
            self.assertIn(
                "101:durable_status_mismatch", result["perEventRetryHistory"]["unknown"]
            )

    def test_unknown_ack_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": UNKNOWN_ACK_HISTORY}),
                row_reader=FakeRowReader(UNKNOWN_ACK_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            per_event = result["perEventRetryHistory"]
            self.assertEqual(per_event["status"], "UNKNOWN")
            self.assertIn("101:attempt_1:outcome_unknown", per_event["unknown"])
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertTrue(result["manual_reconciliation_required"])
            self.assertNoPass(result)

    def test_missing_logs_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({}),
                row_reader=FakeRowReader({}),
                request_log_collector=DynamicRequestLogCollector(probe, mode="empty"),
            )
            per_event = result["perEventRetryHistory"]
            self.assertEqual(per_event["status"], "BLOCKED")
            self.assertEqual(result["status"], "BLOCKED")
            self.assertNoPass(result)

    def test_collector_error_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector(error=RuntimeError("log read failed")),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            self.assertEqual(result["perEventRetryHistory"]["status"], "BLOCKED")
            self.assertTrue(
                any("collect_e3_lines" in problem for problem in result["problems"])
            )
            self.assertNoPass(result)

    def test_missing_row_reader_prevents_pass(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=None,
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            per_event = result["perEventRetryHistory"]
            self.assertEqual(per_event["status"], "BLOCKED")
            self.assertIn(
                "durable_row_reconciliation_unavailable", per_event["unknown"]
            )
            self.assertNoPass(result)

    def test_attempt_bound_exceeded(self) -> None:
        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["bounds"]["max_attempts"] = 1
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                config=config,
                collector=FakeE3Collector({"node-a": BOUND_EXCEEDED_HISTORY}),
                row_reader=FakeRowReader({"evt-1": {"attempts": 2, "status": "SUCCEEDED"}}),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            per_event = result["perEventRetryHistory"]
            self.assertEqual(per_event["status"], "UNKNOWN")
            self.assertEqual(per_event["attemptBoundExceeded"], ["101"])
            self.assertIn("attempt_bound_exceeded", result["problems"])
            self.assertNoPass(result)

    def test_event_id_bound_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            original = e3_runner.MAX_EVENT_IDS
            e3_runner.MAX_EVENT_IDS = 1
            try:
                result = self.run_campaign(
                    Path(raw_tmp),
                    probe=probe,
                    collector=FakeE3Collector({"node-a": TWO_DELTA_HISTORY}),
                    row_reader=FakeRowReader(TWO_DELTA_ROWS),
                    request_log_collector=DynamicRequestLogCollector(probe),
                )
            finally:
                e3_runner.MAX_EVENT_IDS = original
            self.assertIn("event_id_bound_exceeded", result["problems"])
            self.assertEqual(result["perEventRetryHistory"]["status"], "BLOCKED")
            self.assertNoPass(result)

    def test_event_log_bound_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            original = e3_runner.MAX_E3_EVENTS
            e3_runner.MAX_E3_EVENTS = 2
            try:
                result = self.run_campaign(
                    Path(raw_tmp),
                    probe=probe,
                    collector=FakeE3Collector({"node-a": TWO_DELTA_HISTORY}),
                    row_reader=FakeRowReader(TWO_DELTA_ROWS),
                    request_log_collector=DynamicRequestLogCollector(probe),
                )
            finally:
                e3_runner.MAX_E3_EVENTS = original
            self.assertIn("event_log_bound_exceeded", result["problems"])
            self.assertNoPass(result)


class TestOutputCategories(E3RunnerTestCase):
    def test_request_side_skip_when_target_stays_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=allow_everywhere)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            categories = result["outputCategories"]
            self.assertEqual(
                categories[e3_runner.CATEGORY_REQUEST_SIDE]["status"], "SKIP"
            )
            self.assertEqual(categories[e3_runner.CATEGORY_UNRELATED]["status"], "PASS")
            self.assertEqual(categories[e3_runner.CATEGORY_PUBLICATION]["status"], "PASS")
            self.assertEqual(categories[e3_runner.CATEGORY_PER_EVENT]["status"], "PASS")
            self.assertEqual(result["status"], "SKIP")
            self.assertNoPass(result)

    def test_unrelated_pending_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=pending_everywhere)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            categories = result["outputCategories"]
            self.assertEqual(
                categories[e3_runner.CATEGORY_REQUEST_SIDE]["status"], "PASS"
            )
            self.assertEqual(
                categories[e3_runner.CATEGORY_UNRELATED]["status"], "UNKNOWN"
            )
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertNoPass(result)

    def test_publication_unknown_when_indicators_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(
                decision_fn=default_decisions,
                sql_error=RuntimeError("db down"),
                redis_error=RuntimeError("redis down"),
            )
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            categories = result["outputCategories"]
            self.assertEqual(
                categories[e3_runner.CATEGORY_PUBLICATION]["status"], "UNKNOWN"
            )
            self.assertNoPass(result)

    def test_publication_skip_when_not_configured(self) -> None:
        sample_config = E3SampleConfig(row_queries=(), pointer_keys=())
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                sample_config=sample_config,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
            )
            categories = result["outputCategories"]
            self.assertEqual(
                categories[e3_runner.CATEGORY_PUBLICATION]["status"], "SKIP"
            )
            self.assertEqual(result["status"], "SKIP")
            self.assertNoPass(result)

    def test_actor_aware_probe_required_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp),
                probe=SqlOnlyProbe(),
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(None),
            )
            categories = result["outputCategories"]
            self.assertEqual(
                categories[e3_runner.CATEGORY_REQUEST_SIDE]["status"], "BLOCKED"
            )
            self.assertEqual(
                categories[e3_runner.CATEGORY_UNRELATED]["status"], "BLOCKED"
            )
            self.assertEqual(result["status"], "BLOCKED")
            self.assertNoPass(result)

    def test_zero_duration_windows_are_skipped(self) -> None:
        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["windows"]["injection_window_s"] = 0
        config["e3"]["windows"]["drain_window_s"] = 0
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
                config=config,
            )
            self.assertEqual(result["sampling"]["injection_window"]["outcome"], "skipped")
            self.assertEqual(result["sampling"]["drain_window"]["outcome"], "skipped")
            self.assertEqual(result["status"], "SKIP")
            self.assertNoPass(result)


class TestHostAdmissionCrosscheck(E3RunnerTestCase):
    def test_probe_allow_without_admission_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe, mode="empty"),
            )
            crosscheck = result["hostAdmissionCrosscheck"]
            self.assertEqual(crosscheck["status"], "UNKNOWN")
            self.assertGreater(crosscheck["unverified"], 0)
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertNoPass(result)

    def test_probe_allow_host_denial_is_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe, mode="deny_all"),
            )
            crosscheck = result["hostAdmissionCrosscheck"]
            self.assertEqual(crosscheck["status"], "FAIL")
            self.assertIn("probe_host_decision_contradiction", result["problems"])
            self.assertEqual(result["status"], "FAIL")
            self.assertNoPass(result)

    def test_probe_pending_with_host_admission_is_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe, mode="admit_all"),
            )
            crosscheck = result["hostAdmissionCrosscheck"]
            self.assertEqual(crosscheck["status"], "FAIL")
            kinds = {entry["kind"] for entry in crosscheck["contradictions"]}
            self.assertIn("probe_non_admission_with_host_admission", kinds)
            self.assertEqual(result["status"], "FAIL")
            self.assertNoPass(result)

    def test_no_request_log_collector_is_skip(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp),
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=None,
            )
            self.assertEqual(result["hostAdmissionCrosscheck"]["status"], "SKIP")
            self.assertEqual(result["status"], "SKIP")
            self.assertNoPass(result)


class TestNoSensitiveConstants(E3RunnerTestCase):
    _IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

    def test_module_source_has_no_deployment_constants(self) -> None:
        source = (_HERE / "e3_runner.py").read_text(encoding="utf-8")
        self.assertIsNone(self._IPV4_RE.search(source), "no IP literals allowed")
        for token in (
            "http://",
            "https://",
            "mysql_root",
            "redis_password",
            "MYSQL_PWD",
            "REDISCLI_AUTH",
            "hmac_secret",
            "ssh ",
        ):
            self.assertNotIn(token, source, "sensitive constant token found: %s" % token)

    def test_outputs_are_scrubbed(self) -> None:
        config = copy.deepcopy(BASE_CONFIG)
        config["e3"]["decision_node"] = "gateway.example.com"
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            probe = FakeE3Probe(decision_fn=default_decisions)
            result = self.run_campaign(
                tmp,
                probe=probe,
                collector=FakeE3Collector({"node-a": PUBLISH_HISTORY}),
                row_reader=FakeRowReader(PUBLISH_ROWS),
                request_log_collector=DynamicRequestLogCollector(probe),
                config=config,
            )
            self.assertEqual(result["settings"]["decisionNode"], "[redacted-host]")
            # The probe still received the raw logical alias (needed to probe).
            self.assertTrue(any(node == "gateway.example.com" for _r, _c, node, _p in probe.role_calls))
            serialized = json.dumps(result)
            self.assertNotIn("example.com", serialized)


class TestCliModes(unittest.TestCase):
    def test_cli_plan(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            config_path = write_config(tmp)
            out = tmp / "plan_out"
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = e3_runner.main(["plan", "--config", str(config_path), "--out", str(out)])
            self.assertEqual(code, 0)
            plan = json.loads((out / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["status"], "PLANNED")
            experiment_common.verify_checksums(out, out / "checksums.sha256")

    def test_cli_run_without_live_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            config_path = write_config(tmp)
            out = tmp / "run_out"
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = e3_runner.main(["run", "--config", str(config_path), "--out", str(out)])
            self.assertEqual(code, 1)
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "BLOCKED")
            self.assertEqual(manifest["problems"], ["live_not_enabled"])

    def test_cli_bad_config_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            config_path = tmp / "broken.json"
            config_path.write_text(json.dumps({"run_id": "x"}), encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = e3_runner.main(["plan", "--config", str(config_path), "--out", str(tmp / "o")])
            self.assertEqual(code, 2)


class TestApprovalAndPairingGuards(E3RunnerTestCase):
    """Approval-hash capture, marker op-id pairing, and per-epoch pairing."""

    def test_approval_validator_receives_exact_canonical_config_hash(self) -> None:
        expected_hash = e3_runner.config_sha256(BASE_CONFIG)
        captured: List[Tuple[str, str, str]] = []

        def validator(run_id: str, approval_ref: str, config_hash: str) -> bool:
            captured.append((run_id, approval_ref, config_hash))
            return (
                run_id == RUN_ID
                and approval_ref == APPROVAL_REF
                and config_hash == expected_hash
            )

        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(Path(raw_tmp), approval_validator=validator)
        self.assertEqual(captured, [(RUN_ID, APPROVAL_REF, expected_hash)])
        self.assertNotIn("independent_user_approval_not_verified", result["problems"])

    def test_approval_validator_hash_mismatch_blocks_before_probe_or_controller(self) -> None:
        probe = FakeE3Probe(decision_fn=default_decisions)
        controller = FakeController()
        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp),
                probe=probe,
                controller=controller,
                approval_validator=lambda run_id, ref, config_hash: config_hash == "0" * 64,
            )
        self.assertIn("independent_user_approval_not_verified", result["problems"])
        self.assertEqual(controller.calls, [], "controller must not be called when the validator rejects")
        self.assertEqual(probe.role_calls, [], "probe must not be called when the validator rejects")

    def test_approval_validator_exception_fails_closed(self) -> None:
        probe = FakeE3Probe(decision_fn=default_decisions)
        controller = FakeController()

        def validator(run_id: str, approval_ref: str, config_hash: str) -> bool:
            raise RuntimeError("external validator crashed")

        with tempfile.TemporaryDirectory() as raw_tmp:
            result = self.run_campaign(
                Path(raw_tmp), probe=probe, controller=controller, approval_validator=validator
            )
        self.assertIn("independent_user_approval_not_verified", result["problems"])
        self.assertEqual(controller.calls, [])
        self.assertEqual(probe.role_calls, [])
        self.assertNoPass(result)

    def test_marker_operation_id_mismatch_is_reported(self) -> None:
        ops = e3_runner.e3_operation_ids(RUN_ID)
        markers = [
            e3_runner.PhaseMarker(
                marker="injection_start",
                operation_id="not-the-injection-op",
                sequence=1,
                wall_unix_ns=100,
                monotonic_ns=100,
                ack={"present": True},
            ),
            e3_runner.PhaseMarker(
                marker="injection_end",
                operation_id=ops["injection"],
                sequence=2,
                wall_unix_ns=200,
                monotonic_ns=200,
                ack={"present": True},
            ),
            e3_runner.PhaseMarker(
                marker="drain_start",
                operation_id=ops["drain"],
                sequence=3,
                wall_unix_ns=300,
                monotonic_ns=300,
                ack={"present": True},
            ),
            e3_runner.PhaseMarker(
                marker="drain_end",
                operation_id=ops["drain"],
                sequence=4,
                wall_unix_ns=400,
                monotonic_ns=400,
                ack={"present": True},
            ),
        ]
        report = e3_runner.validate_markers(markers, ops)
        self.assertFalse(report["valid"])
        self.assertIn("marker_operation_id_mismatch:injection", report["problems"])

    def test_attempt_pairs_stay_within_one_observation_epoch(self) -> None:
        def ev(name: str, seq: int, wall: int, epoch: str, node: str = "node-a") -> Any:
            return experiment_common.E3Event(
                event=name,
                process_observation_id=epoch,
                sequence=seq,
                wall_unix_ns=wall,
                delta_event_id=seq,
                event_id="evt-%d" % seq,
                operation_id="op-e3-1",
                attempts=1,
                fields={},
                node=node,
            )

        events = [
            # claim in epoch-1, terminal in epoch-2 (worker restart): the
            # sequences are not comparable and must never pair.
            ev("claim_committed", 1, 1_000, "epoch-1"),
            ev("publish_committed", 2, 5_000, "epoch-2"),
            # claim+terminal inside one epoch: the only legal pair.
            ev("claim_committed", 3, 6_000, "epoch-2"),
            ev("publish_committed", 4, 9_000, "epoch-2"),
            # same epoch id on different nodes: still not comparable.
            ev("claim_committed", 10, 20_000, "epoch-3", node="node-b"),
            ev("publish_committed", 11, 21_000, "epoch-3", node="node-a"),
        ]
        summary = e3_runner.accumulate_attempt_time_ns(events)
        self.assertEqual(summary["paired_attempts"], 1)
        self.assertEqual(summary["cumulative_attempt_wall_ns"], 3_000)

    def test_crosscheck_is_unknown_when_one_node_log_fails_to_parse(self) -> None:
        settings = e3_runner.load_e3_config(BASE_CONFIG)
        target_node = settings.nodes[0]

        class BrokenCollector:
            def collect_request_lines(self, node: str, request_ids: Sequence[str]) -> List[str]:
                if node == target_node:
                    # A well-formed-looking observation record with an unsafe
                    # process epoch must fail the parse (never silently skip).
                    return [
                        json.dumps(
                            {
                                "event": "signed_context_bound",
                                "request_id": "req-1",
                                "process_observation_id": "",
                                "event_sequence": 1,
                                "wall_unix_ns": 1758000000000000000,
                                "message": "e1 authorization observation",
                            }
                        )
                    ]
                return []

        problems: List[str] = []
        limitations: List[Dict[str, Any]] = []
        report = e3_runner.crosscheck_host_admissions(
            BrokenCollector(),
            settings,
            {"req-1": "ALLOW"},
            problems,
            limitations,
        )
        self.assertEqual(report["status"], "UNKNOWN", "a failed log parse must stay UNKNOWN")
        self.assertIn("crosscheck_parse_error:%s" % target_node, problems)
        self.assertEqual(report["contradictions"], [])


if __name__ == "__main__":
    unittest.main()
