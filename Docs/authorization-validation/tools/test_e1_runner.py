#!/usr/bin/env python3
"""Offline unit tests for e1_runner.py (Exec-L1; no services, no network).

Every test runs against an injected FakeWorld:

- ``FakeTransport`` implements the verified TrustGraph wire contract
  (permission-rules/check envelope, protected /stats, rule-set entries/bind/
  unbind/bindings) in-process, synthesizes server-style ``e1 authorization
  observation`` log lines (signed_context_bound, candidate_match,
  final_reload_start, evidence_load_result, authoritative_read_*,
  stable_check_end, decision_return, host_admission, source_commit_start/end)
  and simulates durable audit/pointer/outbox state.
- ``FakeRunner`` implements the injected CommandRunner for the docker-mysql
  SELECT path and the ssh log-slice path with canned TSV rows.

The tests never open sockets, never run real subprocesses, never touch SSH,
MySQL, or Redis, and never execute a live mutation. Import safety is audited
by executing the freshly compiled module body under patched I/O primitives.

Run:  python -m unittest discover -s Docs/authorization-validation/tools
      -t Docs/authorization-validation/tools -p "test_e1_runner.py" -v
"""

from __future__ import annotations

import argparse  # noqa: F401  (pre-warm for the audited import)
import base64
import dataclasses  # noqa: F401  (pre-warm)
import hashlib  # noqa: F401  (pre-warm)
import json
import shlex
import socket  # noqa: F401  (pre-warm)
import subprocess  # noqa: F401  (pre-warm)
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.request  # noqa: F401  (pre-warm)
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from unittest import mock

_TOOLS_DIR = str(Path(__file__).resolve().parent)
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

# Pre-import the dependencies so the audited import executes only the
# e1_runner module body (every stdlib dependency is already cached).
import experiment_common  # noqa: E402
import node_adapter  # noqa: E402
import e1_runner  # noqa: E402

RUN_ID = "authz-validation-e1unittest-run-001"
APPROVAL_REF = "appr-2026-e1-0001"
HMAC_SECRET = "unit-test-hmac-secret-0123456789abcdef"
STATS_PATH = "/main/api/v1/stats"
ENTRY_PATH = "/main/api/v1/rule-sets/9071/entries"
BIND_PATH = "/main/api/v1/rule-sets/card/9061/bind"
UNBIND_PATH = "/main/api/v1/rule-sets/card/9061/unbind/9071"
BINDINGS_PATH = "/main/api/v1/rule-sets/card/9061/bindings"
CHECK_PREFIX = "/main/api/v1/permission-rules/check"
ANCHOR_PATH = "/main/api/v1/rule-sets/9071"


def raw_config(hmac_path: str, **e1_overrides: Any) -> Dict[str, Any]:
    e1: Dict[str, Any] = {
        "admin_actor": {
            "user_id": "9031",
            "icard": "9041",
            "card": "9061",
            "domain": "9011",
            "tenant": "9001",
        },
        "allowlist": {
            "card_id": 9061,
            "rule_set_id": 9071,
            "resource_type": "monitor",
            "action_code": "read",
            "ref_type": "BASE",
        },
        "node_rotation": ["node-a"],
        "cycles": 1,
        "readers": 2,
        "max_requests_per_reader": 4,
        "fixture_synthetic": True,
        "reconcile_polls": 3,
        "reconcile_interval_s": 0.0,
    }
    e1.update(e1_overrides)
    return {
        "run_id": RUN_ID,
        "nodes": {
            "node-a": "http://node-a.invalid:8081",
            "node-b": "http://node-b.invalid:8082",
            "node-c": "http://node-c.invalid:8083",
        },
        "ssh": {"node-a": "ops@node-a.invalid", "node-c": "ops@node-c.invalid"},
        "base_dir": "~/fake-e1-run",
        "db": "astral_bench_test",
        "mysql_container": "fake_mysql_container",
        "redis_container": "fake_redis_container",
        "hmac_secret_file": hmac_path,
        "mysql_root": "fake-mysql-root-not-a-secret",
        "redis_password": "fake-redis-pass-not-a-secret",
        "binary_sha256": "a" * 64,
        "source_snapshot_sha256": "b" * 64,
        "source_git_rev": "c" * 40,
        "source_dirty_patch_sha256": "d" * 64,
        "bootstrap_bin_sha256": "e" * 64,
        "source_dirty": False,
        "e1": e1,
    }


# ---------------------------------------------------------------------------
# Fake world: wire contract + server-side E1 event log + durable SQL state.
# ---------------------------------------------------------------------------

_IDENTITY_FIELDS = {
    "tenant_id": 9001,
    "card_id": 9061,
    "grant_id": "rs-9071",
    "grant_revision": 1,
    "grant_hash": "f" * 64,
}
_CANDIDATE_IDENTITY = (
    _IDENTITY_FIELDS["tenant_id"],
    _IDENTITY_FIELDS["card_id"],
    _IDENTITY_FIELDS["grant_id"],
    _IDENTITY_FIELDS["grant_revision"],
    _IDENTITY_FIELDS["grant_hash"],
)
_PROCESS_OBSERVATION_ID = "proc-e1-test"


class FakeWorld:
    """In-process TrustGraph stand-in with deterministic event ordering.

    ``stale_mode`` provides the deterministic stale-ALLOW scenario: reader
    stats requests that arrive before the delete commit are parked and served
    as pre-decided ALLOWs *after* the commit events were emitted. The E0
    evidence stats request (the first one served while the grant is live) is
    never parked, so the campaign thread is never blocked.
    """

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.transport_calls: List[Dict[str, Any]] = []
        self.log_lines: List[str] = []
        self.entries: List[Dict[str, Any]] = []
        self.bound = False
        self.candidate_identity = dict(_IDENTITY_FIELDS)
        self.foreign_bound_cards: List[int] = []
        self.rule_set_tenant: Optional[int] = 9001
        self.rule_set_enabled = True
        self.grant_active = False
        self.admin_denied = False
        self.stats_open_pre_grant = False
        self.next_entry_id = 5000
        self.audit: Dict[str, List[Tuple[str, Optional[int], int]]] = {}
        self.delta_events: List[Dict[str, Any]] = []
        self.current_pointer: Optional[Dict[str, Any]] = None
        self.next_pointer_generation = 0
        self.next_pointer_cas = 0
        self.skip_delete_delta = False
        self.stale_pointer_after_delete = False
        self.head_generations = {"CARD": 10, "RULE_SET": 20}
        self.pending_polls = 0
        self.gen = 100
        self.seq = 1000
        self.fail_delete_once = False
        self.sql_fail_substrings: Tuple[str, ...] = ()
        self.stale_mode = False
        self.delete_committed = False
        self.drop_delete_log_slice = False
        self.queued = 0
        self.stats_200_served = 0
        self.serve_event = threading.Event()
        self.runner_calls: List[Tuple[str, ...]] = []

    # -- server-side E1 event emission --------------------------------------

    def _emit(self, event: str, request_id: str, **fields: Any) -> None:
        with self.lock:
            self.seq += 1
            record = {
                "target": "authz_e1",
                "event": event,
                "request_id": request_id,
                "process_observation_id": _PROCESS_OBSERVATION_ID,
                "event_sequence": self.seq,
                "wall_unix_ns": 1758000000000000000 + self.seq,
                "message": "e1 authorization observation",
            }
            record.update(fields)
            self.log_lines.append(json.dumps(record) + "\n")

    def _emit_allow_chain(self, request_id: str) -> None:
        self._emit("signed_context_bound", request_id)
        self._emit("candidate_match", request_id, **self.candidate_identity)
        self._emit("final_reload_start", request_id, **self.candidate_identity)
        self._emit(
            "authoritative_read_start",
            request_id,
            observation="strict_pending_probe",
            outcome="started",
        )
        self._emit(
            "authoritative_read_end",
            request_id,
            observation="strict_pending_probe",
            outcome="ok",
            pending=False,
        )
        self._emit("evidence_load_result", request_id, source="strict_db")
        self._emit("stable_check_end", request_id, stable=True, **self.candidate_identity)
        self._emit("decision_return", request_id, allowed=True, reason="RULE_MATCH")
        self._emit("host_admission", request_id)

    def _emit_deny_pair(self, request_id: str) -> None:
        self._emit("signed_context_bound", request_id)
        self._emit("decision_return", request_id, allowed=False, reason="DEFAULT_DENY")

    def _append_ruleset_delta(
        self, operation_id: str, event_type: str, *, advance_pointer: bool = True
    ) -> None:
        event_id = "delta-%s-%d" % (operation_id, len(self.delta_events) + 1)
        delta = {
            "event_id": event_id,
            "event_type": event_type,
            "status": "SUCCEEDED",
            "target_version": len(self.delta_events) + 1,
            "card_id": 9061,
            "operation_id": operation_id,
        }
        self.delta_events.append(delta)
        if advance_pointer:
            self.next_pointer_generation += 1
            self.next_pointer_cas += 1
            self.current_pointer = {
                "generation": self.next_pointer_generation,
                "status": "READY",
                "revoke_fence": 0,
                "cas_version": self.next_pointer_cas,
                "event_id": event_id,
                "operation_id": operation_id,
                "card_id": 9061,
            }

    # -- wire contract --------------------------------------------------------

    def handle_stats(self, request_id: str) -> Tuple[int, str]:
        park = (
            self.stale_mode
            and not self.delete_committed
            and self.bound
            and bool(self.entries)
            and self.stats_200_served >= 1
        )
        if park:
            with self.lock:
                self.queued += 1
            self.serve_event.wait(timeout=15.0)
        with self.lock:
            serving_allow = (
                self.grant_active
                or self.stats_open_pre_grant
                or (self.stale_mode and self.delete_committed and self.bound)
            )
            if serving_allow:
                self.stats_200_served += 1
                self._emit_allow_chain(request_id)
                return 200, json.dumps({"code": 200, "message": "ok", "data": {"total": 1}})
            self._emit_deny_pair(request_id)
            return 403, json.dumps(
                {
                    "code": 403,
                    "message": "Permission denied: DEFAULT_DENY for monitor:read",
                    "data": None,
                    "errorType": "PERMISSION_DENIED",
                }
            )

    def handle_delete_entry(self, request_id: str, entry_id: int) -> Tuple[int, str]:
        with self.lock:
            if self.fail_delete_once:
                self.fail_delete_once = False
                raise OSError("injected transport failure (timeout before commit)")
            self.entries = [e for e in self.entries if e["entry_id"] != entry_id]
            self.gen += 1
            self.audit.setdefault(request_id, []).append(("DELETE", entry_id, self.gen))
            if not self.skip_delete_delta:
                self._append_ruleset_delta(
                    request_id,
                    "REMOVE",
                    advance_pointer=not self.stale_pointer_after_delete,
                )
            self._emit(
                "source_commit_start",
                request_id,
                operation_id=request_id,
                mutation="rule_set_entry_delete",
                rule_set_id=9071,
                entry_id=entry_id,
            )
            self._emit(
                "source_commit_end",
                request_id,
                operation_id=request_id,
                mutation="rule_set_entry_delete",
                rule_set_id=9071,
                entry_id=entry_id,
                outcome="committed",
            )
            self.delete_committed = True
            self.grant_active = self.bound and bool(self.entries)
            return 200, json.dumps({"code": 200, "message": "ok", "data": None})

    # -- SELECT-only SQL surface ------------------------------------------------

    def sql(self, query: str) -> str:
        if "SELECT COUNT(*) FROM rule_set WHERE " in query:
            owner_matches = "tenant_id=9001" in query and self.rule_set_tenant == 9001
            active_matches = "enabled=1" in query and self.rule_set_enabled
            return "1\n" if owner_matches and active_matches else "0\n"
        if "SELECT card_id FROM card_rule_set_ref WHERE rule_set_id=" in query:
            rows = list(self.foreign_bound_cards)
            if self.bound:
                rows.append(9061)
            return "".join("%d\n" % card_id for card_id in sorted(set(rows)))
        if "SELECT COUNT(*) FROM rule_set_entry rse " in query and "rse.entry_id=" in query:
            entry_id = int(query.split("rse.entry_id=")[1].split(" ")[0])
            count = sum(1 for e in self.entries if e["entry_id"] == entry_id)
            return "%d\n" % count
        if "FROM rule_set_projection_audit " in query and "operation_id=" in query:
            op_id = query.split("operation_id='")[1].split("'")[0]
            rows = self.audit.get(op_id, [])
            return "".join(
                "9071\t%d\tRULE_SET\t9071\t%s\tevt-%s-%d\t%d\n"
                % (
                    entry if entry is not None else 0,
                    change,
                    op_id[:8],
                    index,
                    generation,
                )
                for index, (change, entry, generation) in enumerate(rows)
            )
        if "FROM authorization_projection_head" in query:
            if "aggregate_type='CARD'" in query:
                return "CARD\t9061\t%d\t0\n" % self.head_generations["CARD"]
            return "RULE_SET\t9071\t%d\t0\n" % self.head_generations["RULE_SET"]
        if "FROM authorization_projection_current" in query:
            if "aggregate_type='USER_CARD'" in query or self.current_pointer is None:
                return ""
            pointer = self.current_pointer
            return "%d\t%s\t%d\t%d\t%s\t%s\t%d\n" % (
                pointer["generation"],
                pointer["status"],
                pointer["revoke_fence"],
                pointer["cas_version"],
                pointer["event_id"],
                pointer["operation_id"],
                pointer["card_id"],
            )
        if "FROM authorization_delta_event" in query:
            if "aggregate_type='USER_CARD'" in query:
                return ""
            events = list(self.delta_events)
            if "operation_id='" in query:
                operation_id = query.split("operation_id='")[1].split("'")[0]
                events = [event for event in events if event["operation_id"] == operation_id]
                return "".join(
                    "%s\t%s\t%s\t%d\t%d\n"
                    % (
                        event["event_id"],
                        event["event_type"],
                        event["status"],
                        event["target_version"],
                        event["card_id"],
                    )
                    for event in events
                )
            if self.pending_polls > 0:
                # never-converging simulation: a non-terminal delta keeps the
                # RuleSet aggregate off the quiescence set (delta-chain predicate)
                return "".join("PENDING\t%d\n" % event["target_version"] for event in events)
            return "".join(
                "%s\t%d\n" % (event["status"], event["target_version"])
                for event in events
            )
        if "FROM authorization_projection_outbox" in query:
            if self.pending_polls > 0:
                if "aggregate_type='CARD'" in query:
                    return "1\t9\tPENDING\t\t0\t\t0\n"
                return "1\t19\tPENDING\t\t0\t\t0\n"
            if "aggregate_type='CARD'" in query:
                return "1\t%d\tPROCESSED\t\t1\tw\t1\n" % self.head_generations["CARD"]
            return "1\t%d\tPROCESSED\t\t1\tw\t1\n" % self.head_generations["RULE_SET"]
        raise AssertionError("unexpected sql: %s" % query)


class FakeTransport:
    """Injected HttpTransport over FakeWorld; records every call."""

    BASE_BY_NODE = {
        "node-a": "http://node-a.invalid:8081",
        "node-b": "http://node-b.invalid:8082",
        "node-c": "http://node-c.invalid:8083",
    }

    def __init__(self, world: FakeWorld) -> None:
        self.world = world

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: Optional[bytes],
        timeout_s: float,
    ) -> Tuple[int, str]:
        world = self.world
        path: Optional[str] = None
        for base in self.BASE_BY_NODE.values():
            if url.startswith(base):
                path = url[len(base):]
                break
        assert path is not None, "unexpected url host: %s" % url
        request_id = str(headers.get("x-request-id", ""))
        world.transport_calls.append(
            {
                "method": method,
                "path": path,
                "requestId": request_id,
                "actorCard": headers.get("x-user-card-id"),
                "actorUser": headers.get("x-user-id"),
            }
        )
        # The stats handler manages its own synchronization and may park a
        # reader waiting for the delete commit; it must therefore run OUTSIDE
        # the coarse world lock or the delete would deadlock behind it.
        if path == STATS_PATH and method == "GET":
            return world.handle_stats(request_id)
        with world.lock:
            if path.startswith(CHECK_PREFIX) and method == "GET":
                effect = "ALLOW" if world.grant_active else "NO_MATCH"
                return 200, json.dumps(
                    {
                        "code": 200,
                        "message": "ok",
                        "data": {
                            "effect": effect,
                            "reason": "RULE_MATCH" if effect == "ALLOW" else "NO_MATCH",
                        },
                    }
                )
            if path == ANCHOR_PATH and method == "GET":
                return 200, json.dumps(
                    {
                        "code": 200,
                        "message": "ok",
                        "data": {
                            "id": 9071,
                            "name": "e1-fixture",
                            "refType": "BASE",
                            "description": None,
                            "entryCount": len(world.entries),
                            "boundCardCount": 1 if world.bound else 0,
                        },
                    }
                )
            if path == ENTRY_PATH and method == "GET":
                rows = [
                    {
                        "id": e["entry_id"],
                        "effect": e["effect"],
                        "resource": e["resource"],
                        "action": e["action"],
                        "priority": 100,
                    }
                    for e in world.entries
                ]
                return 200, json.dumps({"code": 200, "message": "ok", "data": rows})
            if path == ENTRY_PATH and method == "POST":
                payload = json.loads(body.decode("utf-8")) if body else {}
                entry_id = world.next_entry_id
                world.next_entry_id += 1
                world.entries.append(
                    {
                        "entry_id": entry_id,
                        "effect": payload.get("effect"),
                        "resource": payload.get("resource"),
                        "action": payload.get("action"),
                    }
                )
                world.gen += 1
                world.audit.setdefault(request_id, []).append(("CREATE", entry_id, world.gen))
                world.grant_active = world.bound and bool(world.entries)
                return 200, json.dumps(
                    {
                        "code": 200,
                        "message": "ok",
                        "data": {
                            "id": entry_id,
                            "effect": payload.get("effect"),
                            "resource": payload.get("resource"),
                            "action": payload.get("action"),
                            "priority": 100,
                        },
                    }
                )
            if path.startswith(ENTRY_PATH + "/") and method == "DELETE":
                entry_id = int(path.rsplit("/", 1)[-1])
                return world.handle_delete_entry(request_id, entry_id)
            if path == BIND_PATH and method == "POST":
                world.bound = True
                world.gen += 1
                world.audit.setdefault(request_id, []).append(("BIND_CARD", None, world.gen))
                if world.entries:
                    world._append_ruleset_delta(request_id, "ADD")
                world.grant_active = bool(world.entries)
                return 200, json.dumps({"code": 200, "message": "ok", "data": None})
            if path == UNBIND_PATH and method == "DELETE":
                world.bound = False
                world.gen += 1
                world.audit.setdefault(request_id, []).append(("UNBIND_CARD", None, world.gen))
                world.grant_active = False
                return 200, json.dumps({"code": 200, "message": "ok", "data": None})
            if path == BINDINGS_PATH and method == "GET":
                if world.admin_denied:
                    return 403, json.dumps(
                        {"code": 403, "message": "PLATFORM_ADMIN_REQUIRED", "data": None}
                    )
                rows = (
                    [
                        {
                            "ruleSetId": 9071,
                            "ruleSetName": "e1-fixture",
                            "ruleSetCode": "e1-fixture",
                            "refType": "BASE",
                        }
                    ]
                    if world.bound
                    else []
                )
                return 200, json.dumps({"code": 200, "message": "ok", "data": rows})
        raise AssertionError("unexpected request: %s %s" % (method, path))


class FakeRunner:
    """Injected CommandRunner: docker-mysql SELECTs and ssh log slices."""

    def __init__(self, world: FakeWorld) -> None:
        self.world = world

    def run(self, argv: Sequence[str], *, stdin_text: str = "", timeout_s: float = 60.0):
        argv = tuple(str(part) for part in argv)
        self.world.runner_calls.append(argv)
        if argv[0] == "docker":
            query = argv[-1]
            if any(sub in query for sub in self.world.sql_fail_substrings):
                return node_adapter.CommandResult(argv, 1, "", "injected sql failure")
            return node_adapter.CommandResult(argv, 0, self.world.sql(query), "")
        if argv[0] == "ssh":
            payload = shlex.split(argv[-1])[-1]
            identifiers = json.loads(base64.b64decode(payload))
            if self.world.drop_delete_log_slice and self.world.delete_committed:
                return node_adapter.CommandResult(argv, 0, "", "")
            lines = [
                line
                for line in self.world.log_lines
                if any(identifier in line for identifier in identifiers)
            ]
            return node_adapter.CommandResult(argv, 0, "".join(lines), "")
        raise AssertionError("unexpected runner argv: %r" % (argv,))


_CURRENT_CONFIG: List[Dict[str, Any]] = []


def make_adapter(world: FakeWorld) -> node_adapter.NodeAdapter:
    config = node_adapter.load_config(_CURRENT_CONFIG[0])
    actor = node_adapter.Actor.from_mapping(_CURRENT_CONFIG[0]["e1"]["admin_actor"])
    return node_adapter.NodeAdapter(
        config, actor=actor, runner=FakeRunner(world), transport=FakeTransport(world)
    )


# ---------------------------------------------------------------------------
# Synthetic same-process E1 event builders for the pure classifier tests.
# ---------------------------------------------------------------------------


def _line(event: str, seq: int, request_id: str, **fields: Any) -> str:
    record = {
        "event": event,
        "request_id": request_id,
        "process_observation_id": _PROCESS_OBSERVATION_ID,
        "event_sequence": seq,
        "wall_unix_ns": 1758000000000000000 + seq,
        "message": "e1 authorization observation",
    }
    record.update(fields)
    return json.dumps(record)


def allow_request_lines(request_id: str, signed: int) -> List[str]:
    ident = dict(_IDENTITY_FIELDS)
    return [
        _line("signed_context_bound", signed, request_id),
        _line("candidate_match", signed + 10, request_id, **ident),
        _line("final_reload_start", signed + 20, request_id, **ident),
        _line(
            "authoritative_read_start",
            signed + 30,
            request_id,
            observation="strict_pending_probe",
            outcome="started",
        ),
        _line(
            "authoritative_read_end",
            signed + 40,
            request_id,
            observation="strict_pending_probe",
            outcome="ok",
            pending=False,
        ),
        _line("evidence_load_result", signed + 50, request_id, source="strict_db"),
        _line("stable_check_end", signed + 60, request_id, stable=True, **ident),
        _line("decision_return", signed + 70, request_id, allowed=True, reason="RULE_MATCH"),
        _line("host_admission", signed + 80, request_id),
    ]


def pending_request_lines(request_id: str, signed: int) -> List[str]:
    return [
        _line("signed_context_bound", signed, request_id),
        _line(
            "decision_return",
            signed + 10,
            request_id,
            allowed=False,
            reason="AUTHORIZATION_PENDING: evidence not published",
        ),
    ]


def commit_lines(request_id: str, start: int) -> List[str]:
    return [
        _line("source_commit_start", start, request_id, operation_id=request_id),
        _line(
            "source_commit_end",
            start + 1,
            request_id,
            operation_id=request_id,
            outcome="committed",
        ),
    ]


# ---------------------------------------------------------------------------
# The test cases.
# ---------------------------------------------------------------------------


class E1RunnerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="e1_runner_test_")
        base = Path(self._tmp.name)
        self.out = base / "out"
        self.hmac_path = base / "hmac.txt"
        self.hmac_path.write_text(HMAC_SECRET + "\n", encoding="utf-8")
        self.config = raw_config(str(self.hmac_path))
        _CURRENT_CONFIG.clear()
        _CURRENT_CONFIG.append(self.config)

    def tearDown(self) -> None:
        _CURRENT_CONFIG.clear()
        self._tmp.cleanup()

    def _approval_record(self) -> str:
        path = Path(self._tmp.name) / "approval.json"
        path.write_text(
            json.dumps(
                {
                    "run_id": RUN_ID,
                    "approval_ref": APPROVAL_REF,
                    "approval_scope": "E1-LIVE-CAMPAIGN",
                    "approved_by": "human-operator",
                    "approved_at": "2026-09-19T12:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        return str(path)

    def _config_file(self) -> str:
        path = Path(self._tmp.name) / "config.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        return str(path)

    def _run_live(self, world: FakeWorld, out: Optional[Path] = None) -> Dict[str, Any]:
        return e1_runner.execute_campaign(
            self.config,
            out if out is not None else self.out,
            live=True,
            approval_ref=APPROVAL_REF,
            approval_record=self._approval_record(),
            confirm_exec_l3=True,
            approval_validator=lambda run_id, approval_ref, config_sha256: (
                run_id == RUN_ID and approval_ref == APPROVAL_REF and len(config_sha256) == 64
            ),
            adapter_factory=lambda: make_adapter(world),
        )

    # -- 1. import safety and default offline mode ---------------------------

    def test_module_import_performs_no_io(self) -> None:
        source = (Path(_TOOLS_DIR) / "e1_runner.py").read_text(encoding="utf-8")
        code = compile(source, "e1_runner.py", "exec")

        def boom(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("I/O attempted during module import")

        with mock.patch("builtins.open", boom), \
                mock.patch("socket.socket", boom), \
                mock.patch("subprocess.Popen", boom), \
                mock.patch("urllib.request.urlopen", boom), \
                mock.patch("os.mkdir", boom), \
                mock.patch("os.makedirs", boom), \
                mock.patch("os.replace", boom):
            module = types.ModuleType("e1_runner_audited")
            module.__dict__["__name__"] = "e1_runner_audited"
            sys.modules["e1_runner_audited"] = module
            try:
                exec(code, module.__dict__)
            finally:
                del sys.modules["e1_runner_audited"]
        self.assertTrue(hasattr(module, "execute_campaign"))
        self.assertTrue(hasattr(module, "execute_plan"))
        self.assertTrue(hasattr(module, "execute_preflight"))

    def test_plan_mode_never_builds_adapter_or_contacts_nodes(self) -> None:
        with mock.patch.object(
            e1_runner, "_build_adapter", side_effect=AssertionError("adapter built in plan mode")
        ):
            plan = e1_runner.execute_plan(self.config, self.out)
        self.assertEqual(plan["status"], "PLANNED")
        self.assertTrue((self.out / "plan.json").exists())
        self.assertTrue((self.out / "checksums.sha256").exists())
        experiment_common.verify_checksums(self.out, self.out / "checksums.sha256")

    def test_run_mode_without_live_is_offline_and_blocked(self) -> None:
        with mock.patch.object(
            e1_runner, "_build_adapter", side_effect=AssertionError("adapter built offline")
        ):
            exit_code = e1_runner.main(
                ["run", "--config", str(self._config_file()), "--out", str(self.out)]
            )
        self.assertEqual(exit_code, 1)
        manifest = json.loads((self.out / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "BLOCKED")
        self.assertIn("live_not_enabled", manifest["problems"])

    def test_standalone_live_cli_blocks_without_independent_validator(self) -> None:
        with mock.patch.object(
            e1_runner, "_build_adapter", side_effect=AssertionError("adapter built without validator")
        ):
            exit_code = e1_runner.main(
                [
                    "run",
                    "--config",
                    str(self._config_file()),
                    "--out",
                    str(self.out),
                    "--live",
                    "--approval-ref",
                    APPROVAL_REF,
                    "--approval-record",
                    self._approval_record(),
                    "--confirm-exec-l3",
                ]
            )
        self.assertEqual(exit_code, 1)
        manifest = json.loads((self.out / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "BLOCKED")
        self.assertIn("independent_user_approval_not_verified", manifest["problems"])

    # -- 2. plan identity contract --------------------------------------------

    def test_plan_operation_ids_safe_unique_and_ordered(self) -> None:
        plan = e1_runner.execute_plan(self.config, self.out)
        self.assertEqual(plan["operationOrder"], ["addEntry", "bind", "deleteEntry", "unbind"])
        seen: set = set()
        for cycle in plan["cycles"]:
            ops = cycle["operationIds"]
            self.assertEqual(
                sorted(ops), sorted(["addEntry", "bind", "deleteEntry", "unbind"])
            )
            for name, op_id in sorted(ops.items()):
                self.assertLessEqual(len(op_id), 64, name)
                self.assertRegex(op_id, node_adapter.REQUEST_ID_RE.pattern)
                self.assertRegex(op_id, experiment_common.SAFE_ID.pattern)
                seen.add(op_id)
            self.assertEqual(cycle["node"], "node-a")
        self.assertEqual(len(seen), 4 * plan["settings"]["cycles"])
        self.assertEqual(plan["cycles"][0]["readerRequestBudget"], 8)

    # -- 3. preflight is GET/SELECT-only and blocks dirty fixtures -------------

    def test_preflight_uses_get_and_select_only_with_exact_paths(self) -> None:
        world = FakeWorld()
        world.bound = True  # dirty fixture: must block before any mutation
        gate = e1_runner.ReadOnlyGate(make_adapter(world))
        settings = e1_runner.load_e1_config(self.config)[1]
        report = e1_runner.run_preflight_checks(gate, settings, "node-a")
        self.assertEqual(report["status"], "BLOCKED")
        methods = {call["method"] for call in world.transport_calls}
        self.assertEqual(methods, {"GET"})
        paths = sorted(call["path"].split("?")[0] for call in world.transport_calls)
        self.assertEqual(
            paths,
            sorted([CHECK_PREFIX, ANCHOR_PATH, ENTRY_PATH, BINDINGS_PATH, STATS_PATH]),
        )
        for call in world.transport_calls:
            self.assertEqual(call["actorCard"], "9061")
            self.assertTrue(call["path"].startswith("/main/api/v1/"))
        for argv in world.runner_calls:
            self.assertIn(argv[0], ("docker", "ssh"))
            if argv[0] == "docker":
                self.assertTrue(argv[-1].strip().upper().startswith("SELECT"))
        sql_queries = [argv[-1] for argv in world.runner_calls if argv[0] == "docker"]
        self.assertIn(
            "SELECT COUNT(*) FROM rule_set WHERE rule_set_id=9071 AND tenant_id=9001 AND enabled=1",
            sql_queries,
        )
        self.assertIn("card_not_bound_to_rule_set", report["problems"])

    def test_readonly_gate_rejects_mutations(self) -> None:
        gate = e1_runner.ReadOnlyGate(make_adapter(FakeWorld()))
        with self.assertRaises(e1_runner.E1Error):
            gate.signed_request("node-a", "POST", ENTRY_PATH, {})

    def test_preflight_blocks_on_every_dirty_precondition(self) -> None:
        world_entries = FakeWorld()
        world_entries.entries.append(
            {"entry_id": 4001, "effect": "ALLOW", "resource": "monitor", "action": "read"}
        )
        world_bound = FakeWorld()
        world_bound.bound = True
        world_foreign_binding = FakeWorld()
        world_foreign_binding.foreign_bound_cards = [9999]
        world_allow = FakeWorld()
        world_allow.grant_active = True
        world_open = FakeWorld()
        world_open.stats_open_pre_grant = True
        world_admin = FakeWorld()
        world_admin.admin_denied = True
        world_tenantless_rule_set = FakeWorld()
        world_tenantless_rule_set.rule_set_tenant = None
        world_cross_tenant_rule_set = FakeWorld()
        world_cross_tenant_rule_set.rule_set_tenant = 9002
        world_disabled_rule_set = FakeWorld()
        world_disabled_rule_set.rule_set_enabled = False

        cases = [
            ("rule_set_entries_empty", world_entries, None, None),
            ("card_not_bound_to_rule_set", world_bound, None, None),
            ("rule_set_not_bound_to_any_card", world_foreign_binding, None, None),
            ("pre_grant_deny_check_endpoint", world_allow, None, None),
            ("pre_grant_deny_stats", world_open, None, None),
            ("admin_active_and_card_context", world_admin, None, None),
            ("rule_set_owned_by_active_tenant", world_tenantless_rule_set, None, None),
            ("rule_set_owned_by_active_tenant", world_cross_tenant_rule_set, None, None),
            ("rule_set_owned_by_active_tenant", world_disabled_rule_set, None, None),
            ("fixture_synthetic_attestation", FakeWorld(), False, None),
            ("invalid:e1.admin_actor.tenant", FakeWorld(), None, "not-a-tenant"),
            ("invalid:e1.admin_actor.tenant", FakeWorld(), None, str(1 << 63)),
        ]
        try:
            for index, (expected_problem, world, attestation, tenant) in enumerate(cases):
                with self.subTest(problem=expected_problem):
                    if attestation is not None:
                        self.config["e1"]["fixture_synthetic"] = attestation
                    if tenant is not None:
                        self.config["e1"]["admin_actor"]["tenant"] = tenant
                    try:
                        out = Path(self._tmp.name) / ("pf_%d" % index)
                        if tenant is not None:
                            with self.assertRaises(node_adapter.ConfigError) as caught:
                                e1_runner.execute_preflight(
                                    self.config,
                                    out,
                                    gate_factory=lambda w=world: e1_runner.ReadOnlyGate(
                                        make_adapter(w)
                                    ),
                                )
                            self.assertIn(expected_problem, caught.exception.problems)
                            continue
                        report = e1_runner.execute_preflight(
                            self.config,
                            out,
                            gate_factory=lambda w=world: e1_runner.ReadOnlyGate(
                                make_adapter(w)
                            ),
                        )
                    finally:
                        self.config["e1"]["fixture_synthetic"] = True
                        self.config["e1"]["admin_actor"]["tenant"] = "9001"
                    self.assertEqual(report["status"], "BLOCKED")
                    mutations = [
                        c for c in world.transport_calls if c["method"] in ("POST", "DELETE")
                    ]
                    self.assertEqual(mutations, [])
                    self.assertEqual(report["preflight"]["problems"][0], expected_problem)
        finally:
            self.config["e1"]["fixture_synthetic"] = True
            self.config["e1"]["admin_actor"]["tenant"] = "9001"

    def test_preflight_passes_on_clean_fixture(self) -> None:
        report = e1_runner.execute_preflight(
            self.config,
            self.out,
            gate_factory=lambda: e1_runner.ReadOnlyGate(make_adapter(FakeWorld())),
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["preflight"]["problems"], [])

    # -- 4. the explicit multi-factor human live gate ---------------------------

    def test_campaign_requires_full_human_gate_and_never_infers_from_config(self) -> None:
        record = self._approval_record()
        matrix = [
            (
                dict(live=False, approval_ref=None, approval_record=None, confirm_exec_l3=False),
                "live_not_enabled",
            ),
            (
                dict(live=True, approval_ref=None, approval_record=None, confirm_exec_l3=False),
                "exec_l3_human_confirmation_missing",
            ),
            (
                dict(live=True, approval_ref=APPROVAL_REF, approval_record=record,
                     confirm_exec_l3=False),
                "exec_l3_human_confirmation_missing",
            ),
            (
                dict(live=True, approval_ref=None, approval_record=record, confirm_exec_l3=True),
                "approval_ref_missing_or_unsafe",
            ),
            (
                dict(live=True, approval_ref=APPROVAL_REF, approval_record=None,
                     confirm_exec_l3=True),
                "approval_record_missing",
            ),
        ]
        for index, (kwargs, expected) in enumerate(matrix):
            with self.subTest(expected=expected):
                out = Path(self._tmp.name) / ("gate_%d" % index)
                with mock.patch.object(
                    e1_runner,
                    "_build_adapter",
                    side_effect=AssertionError("adapter built without full gate"),
                ):
                    manifest = e1_runner.execute_campaign(self.config, out, **kwargs)
                self.assertEqual(manifest["status"], "BLOCKED")
                self.assertIn(expected, manifest["problems"])

        broken = Path(self._tmp.name) / "broken.json"
        broken.write_text(
            json.dumps({"run_id": "other-run", "approval_ref": APPROVAL_REF}), encoding="utf-8"
        )
        with mock.patch.object(e1_runner, "_build_adapter", side_effect=AssertionError):
            manifest = e1_runner.execute_campaign(
                self.config,
                Path(self._tmp.name) / "gate_mismatch",
                live=True,
                approval_ref=APPROVAL_REF,
                approval_record=str(broken),
                confirm_exec_l3=True,
            )
        self.assertIn("approval_record_run_id_mismatch", manifest["problems"])

        with mock.patch.object(e1_runner, "_build_adapter", side_effect=AssertionError):
            manifest = e1_runner.execute_campaign(
                self.config,
                Path(self._tmp.name) / "gate_self_supplied",
                live=True,
                approval_ref=APPROVAL_REF,
                approval_record=record,
                confirm_exec_l3=True,
            )
        self.assertEqual(manifest["status"], "BLOCKED")
        self.assertIn("independent_user_approval_not_verified", manifest["problems"])

    # -- 5. campaign on the clean fixture ---------------------------------------

    def test_cleanup_does_not_remove_foreign_binding_after_preflight_block(self) -> None:
        world = FakeWorld()
        world.bound = True
        settings = e1_runner.load_e1_config(self.config)[1]
        result, cleanup = e1_runner._run_cycle_with_cleanup(
            make_adapter(world), settings, 1, "node-a", self.out, None
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(world.bound)
        self.assertFalse(any(call["path"] == UNBIND_PATH for call in world.transport_calls))
        self.assertIn("binding_not_campaign_owned", cleanup["residual"])

    def test_candidate_identity_must_match_e0(self) -> None:
        delete_op = "d1e1e1e1-1111-2222-3333-444444444444"
        request_id = "eeeeeeee-1111-2222-3333-444444444444"
        events = experiment_common.parse_authz_events(
            allow_request_lines(request_id, 210) + commit_lines(delete_op, 300),
            "node-a",
        )
        expected = (9001, 9061, "different-grant", 1, "f" * 64)
        rows, _mutation = e1_runner.classify_reader_requests(
            events,
            [{"requestId": request_id, "httpStatus": 200}],
            delete_op,
            expected,
        )
        self.assertEqual(rows[0]["category"], "unclassified-unknown")
        self.assertIn("candidate_identity_does_not_match_e0", rows[0]["problems"])

    def test_ruleset_campaign_uses_only_the_ruleset_delta_chain(self) -> None:
        world = FakeWorld()
        manifest = self._run_live(world, Path(self._tmp.name) / "ruleset_only")
        self.assertEqual(manifest["status"], "PASS", manifest)
        self.assertEqual(manifest["apiContract"]["aggregates"], ["RULE_SET"])
        queries = [argv[-1] for argv in world.runner_calls if argv[0] == "docker"]
        self.assertTrue(any("aggregate_type='RULE_SET'" in query for query in queries))
        self.assertFalse(any("aggregate_type='USER_CARD'" in query for query in queries))

    def test_campaign_durable_reconciliation_queries_are_tenant_scoped(self) -> None:
        world = FakeWorld()
        manifest = self._run_live(world, Path(self._tmp.name) / "tenant_scope")
        self.assertEqual(manifest["status"], "PASS", manifest)
        queries = [argv[-1] for argv in world.runner_calls if argv[0] == "docker"]
        durable_queries = [
            query
            for query in queries
            if any(
                table in query
                for table in (
                    "authorization_delta_event",
                    "authorization_projection_current",
                    "rule_set_projection_audit",
                    "rule_set_entry",
                )
            )
        ]
        self.assertTrue(durable_queries)
        for query in durable_queries:
            self.assertIn("tenant_id=9001", query)
        source_queries = [query for query in durable_queries if "rule_set_entry" in query]
        self.assertEqual(len(source_queries), 1)
        self.assertIn("INNER JOIN rule_set rs ON rs.rule_set_id=rse.rule_set_id", source_queries[0])
        self.assertIn("rs.tenant_id=9001", source_queries[0])

    def test_e0_candidate_tenant_or_card_mismatch_blocks_campaign(self) -> None:
        world = FakeWorld()
        world.candidate_identity["tenant_id"] = 9002
        manifest = self._run_live(world, Path(self._tmp.name) / "wrong_e0_tenant")
        self.assertEqual(manifest["status"], "BLOCKED")
        cycle = json.loads(
            (Path(self._tmp.name) / "wrong_e0_tenant" / "e1-cycle-1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("e0_candidate_scope_mismatch", cycle["problems"])
        self.assertIsNone(cycle["e0Grant"]["candidateIdentity"])
        self.assertEqual(cycle["readerAttempts"], [])

    def test_campaign_clean_fixture_passes_and_cleans_up(self) -> None:
        world = FakeWorld()
        manifest = self._run_live(world)
        self.assertEqual(manifest["status"], "PASS", manifest)
        cycle = manifest["cycles"][0]
        self.assertEqual(cycle["status"], "PASS")
        self.assertEqual(cycle["counts"]["violations"], 0)
        methods = [call["method"] for call in world.transport_calls]
        self.assertEqual(methods.count("POST"), 2)  # add entry + bind
        self.assertEqual(methods.count("DELETE"), 2)  # delete entry + unbind
        self.assertFalse(world.entries)
        self.assertFalse(world.bound)
        self.assertFalse(world.grant_active)
        order = [call["path"] for call in world.transport_calls if call["method"] == "POST"]
        self.assertEqual(order, [ENTRY_PATH, BIND_PATH])
        cycle_doc = json.loads((self.out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        ops = cycle_doc["operationIds"]
        self.assertEqual(
            [call["requestId"] for call in world.transport_calls if call["method"] == "POST"][0],
            ops["addEntry"],
        )
        attempts = cycle_doc["readerAttempts"]
        self.assertLessEqual(len(attempts), 8)
        ids = [attempt["requestId"] for attempt in attempts]
        self.assertEqual(len(ids), len(set(ids)))
        allow_rows = [row for row in cycle_doc["classifications"] if row["decision"] == "ALLOW"]
        self.assertEqual(len(allow_rows), cycle["counts"]["allow"])
        for row in allow_rows:
            self.assertFalse(row["staleAllowViolation"])
        # evidence artifacts + checksums
        for name in (
            "manifest.json",
            "preflight.json",
            "e1-cycle-1.json",
            "e1-cycle-1-cleanup.json",
        ):
            self.assertTrue((self.out / name).exists(), name)
        experiment_common.verify_checksums(self.out, self.out / "checksums.sha256")

    def test_frozen_result_is_immutable(self) -> None:
        frozen = e1_runner.FrozenResult({"status": "PASS"})
        frozen.freeze()
        self.assertTrue(frozen.frozen)
        with self.assertRaises(e1_runner.E1Error):
            frozen["status"] = "FAIL"
        with self.assertRaises(e1_runner.E1Error):
            frozen.update({"status": "FAIL"})
        with self.assertRaises(e1_runner.E1Error):
            frozen.pop("status")
        with self.assertRaises(e1_runner.E1Error):
            frozen.clear()
        with self.assertRaises(e1_runner.E1Error):
            del frozen["status"]

    # -- 6. deterministic stale-ALLOW classification -----------------------------

    def test_stale_allow_reader_is_classified_violation_and_fails_campaign(self) -> None:
        world = FakeWorld()
        world.stale_mode = True

        def releaser() -> None:
            deadline = time.time() + 15.0
            while time.time() < deadline:
                if world.queued >= 1 and world.delete_committed:
                    world.serve_event.set()
                    return
                time.sleep(0.02)
            world.serve_event.set()

        timer = threading.Thread(target=releaser, daemon=True)
        timer.start()
        try:
            manifest = self._run_live(world)
        finally:
            world.serve_event.set()
        self.assertEqual(manifest["status"], "FAIL", manifest)
        cycle = manifest["cycles"][0]
        self.assertGreaterEqual(cycle["counts"]["violations"], 1)
        cycle_doc = json.loads((self.out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        violating = [row for row in cycle_doc["classifications"] if row["staleAllowViolation"]]
        self.assertTrue(violating)
        for row in violating:
            self.assertEqual(row["category"], "post-commit-before-final-observation")
            self.assertTrue(row["theoremDomain"])
        # cleanup still restored the fixture
        cleanup_doc = json.loads(
            (self.out / "e1-cycle-1-cleanup.json").read_text(encoding="utf-8")
        )
        self.assertEqual(cleanup_doc["cleanup"]["residual"], [])
        self.assertFalse(world.bound)
        self.assertFalse(world.entries)

    # -- 7. durable reconciliation is conservative -------------------------------

    def test_unknown_delete_is_reconciled_then_corrected_exactly_once(self) -> None:
        world = FakeWorld()
        world.fail_delete_once = True
        manifest = self._run_live(world)
        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        entry_deletes = [
            call
            for call in world.transport_calls
            if call["method"] == "DELETE" and call["path"].startswith(ENTRY_PATH + "/")
        ]
        self.assertEqual(len(entry_deletes), 2)  # one failed forward + one reconciled corrective
        unbinds = [call for call in world.transport_calls if call["path"] == UNBIND_PATH]
        self.assertEqual(len(unbinds), 1)
        self.assertFalse(world.entries)
        self.assertFalse(world.bound)
        cycle_doc = json.loads((self.out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        self.assertIn("delete_forward_unknown_corrective_deferred", cycle_doc["problems"])
        cleanup_doc = json.loads(
            (self.out / "e1-cycle-1-cleanup.json").read_text(encoding="utf-8")
        )
        self.assertEqual(cleanup_doc["cleanup"]["residual"], [])

    def test_unknown_reconciliation_is_never_retried(self) -> None:
        world = FakeWorld()
        world.fail_delete_once = True
        world.sql_fail_substrings = ("rule_set_projection_audit",)
        manifest = self._run_live(world)
        self.assertEqual(manifest["status"], "UNKNOWN")
        entry_deletes = [
            call
            for call in world.transport_calls
            if call["method"] == "DELETE" and call["path"].startswith(ENTRY_PATH + "/")
        ]
        self.assertEqual(len(entry_deletes), 1)  # no blind retry when reconcile is UNKNOWN
        self.assertEqual(len(world.entries), 1)  # residual source row left in place
        cleanup_doc = json.loads(
            (self.out / "e1-cycle-1-cleanup.json").read_text(encoding="utf-8")
        )
        residuals = cleanup_doc["cleanup"]["residual"]
        self.assertIn("deleteEntry:unknown_not_corrected", residuals)
        self.assertIn("entries_not_empty_after_cleanup", residuals)
        self.assertNotIn("binding_still_present_after_cleanup", residuals)
        manifest_problems = " ".join(manifest["problems"])
        self.assertIn("cycle_1:deleteEntry:unknown_not_corrected", manifest_problems)

    def test_projection_never_converging_is_unknown_and_skips_the_race(self) -> None:
        world = FakeWorld()
        world.pending_polls = 10 ** 9
        manifest = self._run_live(world)
        self.assertEqual(manifest["status"], "UNKNOWN")
        cycle_doc = json.loads((self.out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        self.assertEqual(cycle_doc["readerAttempts"], [])
        self.assertIn("bind_projection_not_quiescent", cycle_doc["problems"])
        entry_deletes = [
            call
            for call in world.transport_calls
            if call["method"] == "DELETE" and call["path"].startswith(ENTRY_PATH + "/")
        ]
        self.assertEqual(len(entry_deletes), 1)  # corrective cleanup delete only
        self.assertFalse(world.entries)
        self.assertFalse(world.bound)

    def test_missing_delete_delta_prevents_pass_despite_quiescent_aggregate_tail(self) -> None:
        world = FakeWorld()
        world.skip_delete_delta = True
        out = Path(self._tmp.name) / "missing_delete_delta"
        manifest = self._run_live(world, out)

        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(delete["reason"], "operation_publication_unproven_after_delete")
        self.assertEqual(
            delete["operationPublication"]["reason"], "operation_delta_cardinality_mismatch"
        )
        self.assertEqual(delete["projection"][0]["state"], "quiescent")
        self.assertFalse(world.entries)
        self.assertFalse(world.bound)

    def test_stale_pointer_after_delete_delta_prevents_pass(self) -> None:
        world = FakeWorld()
        world.stale_pointer_after_delete = True
        out = Path(self._tmp.name) / "stale_delete_pointer"
        manifest = self._run_live(world, out)

        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(delete["reason"], "operation_publication_unproven_after_delete")
        self.assertEqual(
            delete["operationPublication"]["reason"], "operation_pointer_does_not_match_delta"
        )
        self.assertFalse(world.entries)
        self.assertFalse(world.bound)

    def test_delete_audit_for_another_entry_cannot_prove_target_delete(self) -> None:
        world = FakeWorld()
        original_sql = world.sql

        def sql_with_wrong_delete_entry(query: str) -> str:
            output = original_sql(query)
            if "FROM rule_set_projection_audit " not in query or "operation_id=" not in query:
                return output
            lines = output.splitlines()
            rewritten = []
            for line in lines:
                columns = line.split("\t")
                if len(columns) == 7 and columns[4] == "DELETE":
                    columns[1] = "9999"
                rewritten.append("\t".join(columns))
            return "".join(line + "\n" for line in rewritten)

        world.sql = sql_with_wrong_delete_entry  # type: ignore[method-assign]
        out = Path(self._tmp.name) / "wrong_delete_audit_entry"
        manifest = self._run_live(world, out)

        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(delete["reason"], "contradictory_or_missing_reconciliation_evidence")
        self.assertEqual(delete["matchingDeleteAuditRows"], 0)
        self.assertFalse(world.entries)
        self.assertFalse(world.bound)

    def test_delete_audit_with_wrong_aggregate_scope_cannot_prove_target_delete(self) -> None:
        world = FakeWorld()
        original_sql = world.sql

        def sql_with_wrong_delete_aggregate(query: str) -> str:
            output = original_sql(query)
            if "FROM rule_set_projection_audit " not in query or "operation_id=" not in query:
                return output
            lines = []
            for line in output.splitlines():
                columns = line.split("\t")
                if len(columns) == 7 and columns[4] == "DELETE":
                    columns[2] = "USER_CARD"
                    columns[3] = "9061"
                lines.append("\t".join(columns))
            return "".join(line + "\n" for line in lines)

        world.sql = sql_with_wrong_delete_aggregate  # type: ignore[method-assign]
        out = Path(self._tmp.name) / "wrong_delete_audit_aggregate"
        manifest = self._run_live(world, out)
        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(delete["reason"], "contradictory_or_missing_reconciliation_evidence")
        self.assertEqual(delete["matchingDeleteAuditRows"], 0)

    def test_source_row_present_prevents_operation_publication_claim(self) -> None:
        world = FakeWorld()
        original_sql = world.sql

        def sql_with_source_row_present(query: str) -> str:
            if "SELECT COUNT(*) FROM rule_set_entry rse " in query and "rse.entry_id=" in query:
                return "1\n"
            return original_sql(query)

        world.sql = sql_with_source_row_present  # type: ignore[method-assign]
        out = Path(self._tmp.name) / "source_row_still_present"
        manifest = self._run_live(world, out)
        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(delete["reason"], "contradictory_or_missing_reconciliation_evidence")
        self.assertEqual(delete["sourceRowCount"], 1)

    def test_empty_count_result_is_unknown_not_source_absence(self) -> None:
        world = FakeWorld()
        original_sql = world.sql

        def sql_with_empty_count(query: str) -> str:
            if "SELECT COUNT(*) FROM rule_set_entry rse " in query and "rse.entry_id=" in query:
                return ""
            return original_sql(query)

        world.sql = sql_with_empty_count  # type: ignore[method-assign]
        out = Path(self._tmp.name) / "empty_source_count"
        manifest = self._run_live(world, out)
        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(delete["reason"], "reconciliation_read_failed")
        self.assertIsNone(delete["sourceRowCount"])

    def test_duplicate_matching_delete_audits_prevent_pass(self) -> None:
        world = FakeWorld()
        original_sql = world.sql

        def sql_with_duplicate_delete_audit(query: str) -> str:
            output = original_sql(query)
            if "FROM rule_set_projection_audit " not in query or "operation_id=" not in query:
                return output
            delete_lines = [
                line for line in output.splitlines() if len(line.split("\t")) == 7 and line.split("\t")[4] == "DELETE"
            ]
            if not delete_lines:
                return output
            return output + delete_lines[0] + "\n"

        world.sql = sql_with_duplicate_delete_audit  # type: ignore[method-assign]
        out = Path(self._tmp.name) / "duplicate_delete_audit"
        manifest = self._run_live(world, out)

        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(delete["reason"], "contradictory_or_missing_reconciliation_evidence")
        self.assertEqual(delete["matchingDeleteAuditRows"], 2)
        self.assertFalse(world.entries)
        self.assertFalse(world.bound)

    def test_operation_delta_attribute_mismatches_prevent_pass(self) -> None:
        mutations = {
            "wrong_event_type": (1, "ADD"),
            "non_terminal_status": (2, "PENDING"),
            "wrong_card": (4, "9999"),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                world = FakeWorld()
                original_sql = world.sql

                def sql_with_bad_delta(query: str, *, _mutation: Tuple[Any, ...] = mutation) -> str:
                    output = original_sql(query)
                    if "FROM authorization_delta_event" not in query or "operation_id='" not in query:
                        return output
                    lines = []
                    for line in output.splitlines():
                        columns = line.split("\t")
                        if len(columns) != 5:
                            lines.append(line)
                            continue
                        index, value = _mutation
                        columns[index] = str(value)
                        lines.append("\t".join(columns))
                    return "".join(line + "\n" for line in lines)

                world.sql = sql_with_bad_delta  # type: ignore[method-assign]
                out = Path(self._tmp.name) / ("bad_delta_" + label)
                manifest = self._run_live(world, out)
                self.assertEqual(manifest["status"], "UNKNOWN", manifest)
                cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
                delete = cycle["durable"]["deleteEntry"]
                self.assertEqual(delete["state"], "unknown")
                self.assertEqual(delete["reason"], "operation_publication_unproven_after_delete")
                self.assertEqual(
                    delete["operationPublication"]["reason"],
                    "operation_delta_not_terminal_or_scope_mismatch",
                )

    def test_duplicate_operation_deltas_prevent_pass(self) -> None:
        world = FakeWorld()
        original_sql = world.sql

        def sql_with_duplicate_delta(query: str) -> str:
            output = original_sql(query)
            if "FROM authorization_delta_event" not in query or "operation_id='" not in query:
                return output
            lines = output.splitlines()
            return output + (lines[0] + "\n" if lines else "")

        world.sql = sql_with_duplicate_delta  # type: ignore[method-assign]
        out = Path(self._tmp.name) / "duplicate_operation_delta"
        manifest = self._run_live(world, out)
        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(
            delete["operationPublication"]["reason"], "operation_delta_cardinality_mismatch"
        )
        self.assertEqual(delete["operationPublication"]["deltaRows"], 2)

    def test_pointer_card_mismatch_prevents_pass(self) -> None:
        world = FakeWorld()
        original_sql = world.sql

        def sql_with_wrong_pointer_card(query: str) -> str:
            output = original_sql(query)
            if "FROM authorization_projection_current" not in query:
                return output
            lines = []
            for line in output.splitlines():
                columns = line.split("\t")
                if len(columns) == 7:
                    columns[6] = "9999"
                lines.append("\t".join(columns))
            return "".join(line + "\n" for line in lines)

        world.sql = sql_with_wrong_pointer_card  # type: ignore[method-assign]
        out = Path(self._tmp.name) / "wrong_pointer_card"
        manifest = self._run_live(world, out)
        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads((out / "e1-cycle-1.json").read_text(encoding="utf-8"))
        delete = cycle["durable"]["deleteEntry"]
        self.assertEqual(delete["state"], "unknown")
        self.assertEqual(
            delete["operationPublication"]["reason"], "operation_pointer_does_not_match_delta"
        )

    def test_projection_snapshot_malformed_durable_rows_are_unknown(self) -> None:
        class MalformedAdapter:
            def __init__(self, delta_rows: List[List[str]], pointer_rows: List[List[str]]) -> None:
                self._delta_rows = delta_rows
                self._pointer_rows = pointer_rows

            def delta_states(
                self, _tenant_id: int, _aggregate_type: str, _aggregate_id: int
            ) -> List[List[str]]:
                return self._delta_rows

            def projection_pointer(
                self, _tenant_id: int, _aggregate_type: str, _aggregate_id: int
            ) -> List[List[str]]:
                return self._pointer_rows

        cases = [
            ([["SUCCEEDED"]], [["1", "READY", "0", "1"]], "malformed_delta_rows"),
            ([["SUCCEEDED", "not-an-int"]], [["1", "READY", "0", "1"]], "malformed_delta_rows"),
            ([["SUCCEEDED", "1"]], [["1"]], "malformed_projection_pointer"),
            (
                [["SUCCEEDED", "1"]],
                [["1", "READY", "0", "1"], ["2", "READY", "0", "2"]],
                "multiple_projection_pointers",
            ),
        ]
        for delta_rows, pointer_rows, expected_problem in cases:
            with self.subTest(problem=expected_problem):
                snapshot = e1_runner.projection_snapshot(
                    MalformedAdapter(delta_rows, pointer_rows), 9001, "RULE_SET", 9071
                )
                self.assertEqual(snapshot["state"], "unknown")
                self.assertIn(expected_problem, snapshot["problems"])

    def test_successful_empty_post_race_log_slice_is_unknown(self) -> None:
        world = FakeWorld()
        world.drop_delete_log_slice = True
        manifest = self._run_live(world, Path(self._tmp.name) / "empty_log_slice")
        self.assertEqual(manifest["status"], "UNKNOWN", manifest)
        cycle = json.loads(
            (Path(self._tmp.name) / "empty_log_slice" / "e1-cycle-1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("log_slice_returned_no_e1_events", cycle["problems"])
        self.assertEqual(cycle["classifications"], [])
        self.assertGreater(cycle["counts"]["unknown"], 0)
        # 确定性不变式(替代原 racy ">0" 断言):unclassified 必须精确等于
        # 成功(200)读者尝试数——空日志切片下没有任何尝试可被分类,成功
        # 尝试全部计为 unclassified;两者之差永远是缺陷信号。
        reader_200s = sum(
            1
            for attempt in cycle["readerAttempts"]
            if attempt.get("httpStatus") == 200
        )
        self.assertEqual(cycle["counts"]["unclassified"], reader_200s)

    def test_missing_delete_audit_correlation_prevents_pass(self) -> None:
        world = FakeWorld()

        original_sql = world.sql

        def sql_without_delete_audit(query: str) -> str:
            output = original_sql(query)
            if "FROM rule_set_projection_audit " in query and "operation_id=" in query:
                op_id = query.split("operation_id='")[1].split("'")[0]
                rows = [row for row in world.audit.get(op_id, []) if row[0] != "DELETE"]
                return "".join(
                    "9071\t%d\tRULE_SET\t9071\t%s\tevt-%s-%d\t%d\n"
                    % (
                        entry if entry is not None else 0,
                        change,
                        op_id[:8],
                        index,
                        generation,
                    )
                    for index, (change, entry, generation) in enumerate(rows)
                )
            return output

        world.sql = sql_without_delete_audit  # type: ignore[method-assign]
        manifest = self._run_live(world, Path(self._tmp.name) / "no_audit")
        self.assertEqual(manifest["status"], "UNKNOWN")
        cycle_doc = json.loads(
            (Path(self._tmp.name) / "no_audit" / "e1-cycle-1.json").read_text(encoding="utf-8")
        )
        self.assertIn("delete_durable_postcondition_unproven", cycle_doc["problems"])

    # -- 8. pure classifier mapping (no threads, deterministic) ------------------

    def test_classify_pre_commit_before_single_commit_interval(self) -> None:
        delete_op = "d1e1e1e1-1111-2222-3333-444444444444"
        request_id = "eeeeeeee-1111-2222-3333-444444444444"
        # request 210..290, commit 300..301: admission(290) < commit.start(300)
        lines = allow_request_lines(request_id, 210) + commit_lines(delete_op, 300)
        events = experiment_common.parse_authz_events(lines, "node-a")
        rows, mutation = e1_runner.classify_reader_requests(
            events,
            [{"requestId": request_id, "httpStatus": 200}],
            delete_op,
            _CANDIDATE_IDENTITY,
        )
        self.assertTrue(mutation["commitIntervalProven"])
        self.assertEqual(rows[0]["category"], "pre-commit")
        self.assertFalse(rows[0]["staleAllowViolation"])
        self.assertFalse(rows[0]["theoremDomain"])

    def test_classify_stale_allow_after_commit_is_violation(self) -> None:
        delete_op = "d1e1e1e1-1111-2222-3333-444444444444"
        request_id = "bbbbbbbb-1111-2222-3333-444444444444"
        # commit 1..2 strictly before the final observation (140,150)
        lines = commit_lines(delete_op, 1) + allow_request_lines(request_id, 110)
        events = experiment_common.parse_authz_events(lines, "node-a")
        rows, _mutation = e1_runner.classify_reader_requests(
            events,
            [{"requestId": request_id, "httpStatus": 200}],
            delete_op,
            _CANDIDATE_IDENTITY,
        )
        self.assertEqual(rows[0]["category"], "post-commit-before-final-observation")
        self.assertTrue(rows[0]["staleAllowViolation"])
        self.assertTrue(rows[0]["theoremDomain"])

    def test_classify_commit_overlapping_observation_stays_unknown(self) -> None:
        delete_op = "d1e1e1e1-1111-2222-3333-444444444444"
        request_id = "cccccccc-1111-2222-3333-444444444444"
        # commit 45..46 intersects the observation interval (40,50)
        lines = allow_request_lines(request_id, 10) + commit_lines(delete_op, 45)
        events = experiment_common.parse_authz_events(lines, "node-a")
        rows, _mutation = e1_runner.classify_reader_requests(
            events,
            [{"requestId": request_id, "httpStatus": 200}],
            delete_op,
            _CANDIDATE_IDENTITY,
        )
        self.assertEqual(rows[0]["category"], "interval-overlap-unknown")
        self.assertFalse(rows[0]["staleAllowViolation"])

    def test_classify_pending_and_transport_failures(self) -> None:
        delete_op = "d1e1e1e1-1111-2222-3333-444444444444"
        pending_id = "dddddddd-1111-2222-3333-444444444444"
        lost_id = "11111111-1111-2222-3333-444444444444"
        lines = commit_lines(delete_op, 1) + pending_request_lines(pending_id, 300)
        events = experiment_common.parse_authz_events(lines, "node-a")
        rows, _mutation = e1_runner.classify_reader_requests(
            events,
            [
                {"requestId": pending_id, "httpStatus": 403},
                {"requestId": lost_id, "httpStatus": None, "error": "URLError"},
            ],
            delete_op,
        )
        by_id = {row["requestId"]: row for row in rows}
        self.assertEqual(by_id[pending_id]["decision"], "PENDING")
        self.assertEqual(by_id[lost_id]["decision"], "UNKNOWN")
        self.assertIn("URLError", by_id[lost_id]["problems"])

    def test_classify_without_e0_identity_stays_unclassified(self) -> None:
        delete_op = "d1e1e1e1-1111-2222-3333-444444444444"
        request_id = "aaaaaaaa-1111-2222-3333-444444444444"
        lines = commit_lines(delete_op, 1) + allow_request_lines(request_id, 110)
        events = experiment_common.parse_authz_events(lines, "node-a")
        rows, _mutation = e1_runner.classify_reader_requests(
            events, [{"requestId": request_id, "httpStatus": 200}], delete_op, None
        )
        row = rows[0]
        self.assertEqual(row["decision"], "ALLOW")
        self.assertEqual(row["category"], "unclassified-unknown")
        self.assertFalse(row["staleAllowViolation"])
        self.assertIn("e0_identity_unproven", row["problems"])

    def test_classify_without_commit_interval_stays_unclassified(self) -> None:
        request_id = "aaaaaaaa-1111-2222-3333-444444444444"
        delete_op = "bbbbbbbb-1111-2222-3333-444444444444"
        lines = allow_request_lines(request_id, 10)
        events = experiment_common.parse_authz_events(lines, "node-a")
        rows, mutation = e1_runner.classify_reader_requests(
            events,
            [{"requestId": request_id, "httpStatus": 200}],
            delete_op,
            _CANDIDATE_IDENTITY,
        )
        self.assertFalse(mutation["commitIntervalProven"])
        self.assertEqual(rows[0]["category"], "unclassified-unknown")
        self.assertEqual(rows[0]["decision"], "ALLOW")

    def test_classify_incomplete_request_events_stays_unknown(self) -> None:
        delete_op = "d1e1e1e1-1111-2222-3333-444444444444"
        request_id = "aaaaaaaa-1111-2222-3333-444444444444"
        # candidate_match lacks the exact grant identity -> EvidenceError path
        lines = commit_lines(delete_op, 1) + [
            _line("signed_context_bound", 10, request_id),
            _line("candidate_match", 20, request_id, tenant_id=9001, card_id=9061),
            _line("final_reload_start", 30, request_id, tenant_id=9001, card_id=9061),
            _line("evidence_load_result", 40, request_id, source="strict_db"),
            _line("stable_check_end", 50, request_id, stable=True),
            _line("decision_return", 60, request_id, allowed=True, reason="RULE_MATCH"),
            _line("host_admission", 70, request_id),
        ]
        events = experiment_common.parse_authz_events(lines, "node-a")
        rows, _mutation = e1_runner.classify_reader_requests(
            events, [{"requestId": request_id, "httpStatus": 200}], delete_op
        )
        self.assertEqual(rows[0]["category"], "unclassified-unknown")
        self.assertTrue(rows[0]["problems"])

    # -- 9. two-node rotation, cross-cycle identity, cleanup durability ----------

    def test_plan_rotates_nodes_and_keeps_ids_unique_across_cycles(self) -> None:
        config = raw_config(str(self.hmac_path), node_rotation=["node-a", "node-b"], cycles=2)
        plan = e1_runner.execute_plan(config, self.out)
        self.assertEqual(
            [cycle["node"] for cycle in plan["cycles"]], ["node-a", "node-b"]
        )

        seen_ops = set()
        seen_requests = set()
        for cycle in plan["cycles"]:
            for name, op_id in cycle["operationIds"].items():
                self.assertNotIn(op_id, seen_ops, name)
                seen_ops.add(op_id)
        for cycle in range(1, 3):
            for reader in range(1, 3):
                for sequence in range(1, 5):
                    request_id = e1_runner.reader_request_id(RUN_ID, cycle, reader, sequence)
                    self.assertNotIn(request_id, seen_requests)
                    seen_requests.add(request_id)
        self.assertEqual(len(seen_ops), 4 * 2)
        self.assertEqual(len(seen_requests), 2 * 2 * 4)

    def test_two_cycles_on_one_node_use_distinct_e0_request_ids(self) -> None:
        self.config["e1"]["cycles"] = 2
        _CURRENT_CONFIG[0] = self.config
        world = FakeWorld()
        manifest = self._run_live(world)

        self.assertEqual(manifest["status"], "PASS", manifest)
        self.assertEqual([cycle["status"] for cycle in manifest["cycles"]], ["PASS", "PASS"])
        e0_stats_calls = [
            call
            for call in world.transport_calls
            if call["method"] == "GET" and call["path"] == STATS_PATH
        ]
        e0_ids = [
            call["requestId"]
            for call in e0_stats_calls
            if call["requestId"]
            in {
                e1_runner.stable_id(RUN_ID, "e1:c1:e0:stats"),
                e1_runner.stable_id(RUN_ID, "e1:c2:e0:stats"),
            }
        ]
        self.assertEqual(
            e0_ids,
            [
                e1_runner.stable_id(RUN_ID, "e1:c1:e0:stats"),
                e1_runner.stable_id(RUN_ID, "e1:c2:e0:stats"),
            ],
        )
        for cycle in (1, 2):
            document = json.loads(
                (self.out / ("e1-cycle-%d.json" % cycle)).read_text(encoding="utf-8")
            )
            self.assertEqual(document["e0Grant"]["candidateIdentity"], list(_CANDIDATE_IDENTITY))

    def test_cycle_exception_still_writes_per_cycle_cleanup_artifact(self) -> None:
        world = FakeWorld()
        out = Path(self._tmp.name) / "boom"
        adapter = make_adapter(world)
        settings = e1_runner.load_e1_config(self.config)[1]
        with mock.patch.object(
            e1_runner, "_run_single_cycle", side_effect=RuntimeError("boom")
        ):
            result, cleanup = e1_runner._run_cycle_with_cleanup(
                adapter, settings, 1, "node-a", out, None
            )
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("cycle_exception:RuntimeError", result["problems"])
        cleanup_doc = json.loads(
            (out / "e1-cycle-1-cleanup.json").read_text(encoding="utf-8")
        )
        self.assertEqual(cleanup_doc["cycle"], 1)
        self.assertEqual(cleanup_doc["node"], "node-a")
        # The artifact records the real cleanup outcome (the cycle failure
        # itself lives in the frozen cycle result), and the returned cleanup
        # matches the sealed artifact byte-for-byte in content.
        self.assertEqual(
            sorted(cleanup_doc["cleanup"]),
            ["corrective", "finalBound", "finalEntriesEmpty", "residual", "skipped"],
        )
        self.assertEqual(cleanup, cleanup_doc["cleanup"])

    def test_reader_threads_active_blocks_cleanup_mutations(self) -> None:
        world = FakeWorld()
        adapter = make_adapter(world)
        settings = e1_runner.load_e1_config(self.config)[1]
        cycle_ops = e1_runner.operation_ids_for_cycle(RUN_ID, 1)
        state = {
            "readerThreadsActive": True,
            "entryId": 4100,
            "entryOwnershipProven": True,
            "bindOwnershipProven": True,
            "bindAttempted": True,
        }
        cleanup = e1_runner._cleanup_after_cycle(
            adapter, settings, "node-a", cycle_ops, state, None
        )
        self.assertIn(
            "reader_threads_still_active_manual_reconciliation_required",
            cleanup["residual"],
        )
        self.assertTrue(cleanup["manualReconciliationRequired"])
        self.assertIn("deleteEntry:reader_threads_active", cleanup["skipped"])
        self.assertIn("unbind:reader_threads_active", cleanup["skipped"])
        mutations = [
            call for call in world.transport_calls if call["method"] in ("POST", "DELETE")
        ]
        self.assertEqual(mutations, [], "cleanup must not mutate while readers are active")

    def test_cross_epoch_request_events_classify_unknown_not_stale(self) -> None:
        # A process restart inside one request spans two observation epochs:
        # the classification must refuse to order sequences across epochs and
        # degrade to unclassified-unknown, never to a stale/non-stale verdict.
        delete_op = "d1e1e1e1-1111-2222-3333-444444444444"
        request_id = "aaaaaaaa-1111-2222-3333-444444444444"
        ident = dict(_IDENTITY_FIELDS)
        lines = commit_lines(delete_op, 1) + [
            _line("signed_context_bound", 10, request_id, process_observation_id="proc-older"),
            _line(
                "candidate_match",
                20,
                request_id,
                process_observation_id=_PROCESS_OBSERVATION_ID,
                **ident,
            ),
            _line("final_reload_start", 30, request_id, **ident),
            _line("evidence_load_result", 40, request_id, source="strict_db"),
            _line("stable_check_end", 50, request_id, stable=True),
            _line("decision_return", 60, request_id, allowed=True, reason="RULE_MATCH"),
            _line("host_admission", 70, request_id),
        ]
        events = experiment_common.parse_authz_events(lines, "node-a")
        rows, _mutation = e1_runner.classify_reader_requests(
            events, [{"requestId": request_id, "httpStatus": 200}], delete_op
        )
        row = rows[0]
        self.assertEqual(row["decision"], "ALLOW")
        self.assertEqual(row["category"], "unclassified-unknown")
        self.assertFalse(row["staleAllowViolation"])
        self.assertFalse(row["theoremDomain"])
        self.assertTrue(row["problems"])


if __name__ == "__main__":
    unittest.main()
