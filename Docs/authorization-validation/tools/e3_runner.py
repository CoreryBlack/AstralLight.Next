#!/usr/bin/env python3
"""Recovery-tail validation runner for the authorization runtime.

Orchestrates ``Docs/authorization-validation/VALIDATION_PROTOCOL.md`` E3 (recovery
tail and request-side availability) around an injected fault-injection
controller:

    begin_injection -> [fixed-interval decision sampling window]
    end_injection   -> begin_drain -> [fixed-interval decision sampling window]
    end_drain       -> collect durable per-attempt E3 event logs via an
                       injected collector -> reconcile against durable rows
                       -> four output categories + overall verdict

Safety boundary (AGENTS.md execution tiers; this file is Exec-L1 code with
offline fake tests only):

- Importing this module performs no I/O. The default CLI mode is ``plan``
  (offline, status ``PLANNED``); ``run`` without the full live gate is
  ``BLOCKED`` and constructs nothing. CLI evidence writes are limited to the
  local ``--out`` evidence directory (plan.json / manifest.json + checksums),
  exactly like ``e1_runner.py``.
- NO injected side effect can happen unless ALL of the following held before
  the first controller call: explicit ``allow_live_execution=True``, a valid
  external approval reference plus an approval record bound to the run id,
  an isolated-fixture allowlist in the config, and BOTH an injected probe and
  an injected injection controller. This module ships NO real controller,
  probe, collector, or row reader -- the platform primitives belong to the
  separately gated campaign harness. A bare CLI ``run --live`` is therefore
  always BLOCKED; live mutation/fault injection is a future Exec-L3 action
  and must NEVER be exercised from here.
- Dispatch budget: each controller phase is attempted AT MOST ONCE. On a
  controller error or timeout the runner stops immediately (no retry, no
  cleanup), reports ``UNKNOWN`` with ``manual_reconciliation_required`` and
  flags whether the injection/drain may still be active on the host.
- Sampling goes through ``e3_e4.sample_e3`` with a streaming sink; samples
  are digested with request ids retained, and every decision carries
  ``decision_basis="probe_level"``. A probe-level ALLOW is NOT host
  admission; host admission is only ever asserted by the separate request
  side cross-check (and a contradiction is a hard FAIL).
- Per-attempt verdicts come from ``experiment_common.parse_e3_events`` +
  ``validate_e3_attempt_history`` over injected collector lines, reconciled
  against durable rows from an injected row reader. A PASS requires exact
  durable reconciliation, all four output categories, and complete, ordered
  marker intervals; anything unprovable degrades to SKIP/UNKNOWN/BLOCKED and
  never collapses into PASS.
- Sampling duration, interval, sample count, and per-event attempt count are
  hard-bounded. Markers record both wall (``wall_unix_ns``) and monotonic
  (``monotonic_ns``) time. No hosts, secrets, or sensitive deployment
  constants are embedded anywhere in this file.

Python 3.8+ standard library only. Offline unit tests live in
``test_e3_runner.py`` next to this file and use in-memory fakes only; no
services, containers, sockets, or migrations are involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    runtime_checkable,
)

import e3_e4
from e3_e4 import E3SampleConfig, sample_e3
import experiment_common
from experiment_common import (
    EvidenceError,
    atomic_json,
    parse_authz_events,
    parse_e3_events,
    stable_id,
    validate_e3_attempt_history,
    write_checksums,
)

__all__ = [
    "E3_CLAIM_FULL",
    "E3_CLAIM_NONE",
    "E3Settings",
    "E3RunnerError",
    "ConfigError",
    "PhaseMarker",
    "MARKER_NAMES",
    "RECONCILIATION_PROMPT",
    "config_sha256",
    "crosscheck_host_admissions",
    "e3_operation_ids",
    "execute_campaign",
    "execute_plan",
    "load_e3_config",
    "validate_markers",
    "worst_status",
    "build_parser",
    "main",
]

# ---------------------------------------------------------------------------
# Statuses and bounds.
# ---------------------------------------------------------------------------

#: Worst-first ranking (FAIL is a proven violation; an empty set is BLOCKED
#: because nothing was proven). Mirrors e3_e4.py / AGENTS.md section 7.1.
_STATUS_RANK = {"FAIL": 0, "BLOCKED": 1, "UNKNOWN": 2, "PENDING": 3, "SKIP": 4, "PASS": 5}


def worst_status(statuses: Sequence[str]) -> str:
    """Aggregate statuses into the worst one; an empty set is BLOCKED."""
    items = list(statuses)
    if not items:
        return "BLOCKED"
    return min(items, key=lambda status: _STATUS_RANK.get(status, _STATUS_RANK["UNKNOWN"]))


MIN_INTERVAL_S = 0.01
MAX_INTERVAL_S = 600.0
MAX_WINDOW_S = 3600.0
MAX_SAMPLES_PER_WINDOW = 10000
MAX_ATTEMPTS = 64
MIN_CONTROLLER_TIMEOUT_S = 0.05
MAX_CONTROLLER_TIMEOUT_S = 600.0
DEFAULT_CONTROLLER_TIMEOUT_S = 30.0
MAX_NODES = 4
MAX_E3_EVENTS = 20000
MAX_EVENT_IDS = 512
MAX_CROSSCHECK_REQUEST_IDS = 256

MARKER_NAMES: Tuple[str, ...] = ("injection_start", "injection_end", "drain_start", "drain_end")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$")
_REQUEST_CONTEXT_FIELDS = ("user_id", "tenant_id", "card_id", "resource", "action")
_MARKER_EFFECT_STATES = {
    "injection_start": "ACTIVE",
    "injection_end": "INACTIVE",
    "drain_start": "DRAINING",
    "drain_end": "DRAINED",
}

#: The four protocol E3 output categories; a full claim requires ALL of them.
CATEGORY_REQUEST_SIDE = "request_side_denial_pending"
CATEGORY_UNRELATED = "unrelated_card_availability"
CATEGORY_PUBLICATION = "publication_drain"
CATEGORY_PER_EVENT = "per_event_retry_history"
OUTPUT_CATEGORIES: Tuple[str, ...] = (
    CATEGORY_REQUEST_SIDE,
    CATEGORY_UNRELATED,
    CATEGORY_PUBLICATION,
    CATEGORY_PER_EVENT,
)

E3_CLAIM_FULL = "RECOVERY_TAIL_FULL"
E3_CLAIM_NONE = "NOT_CLAIMED"

APPROVAL_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_CARD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

RECONCILIATION_PROMPT = (
    "MANUAL_RECONCILIATION_REQUIRED: durable injection/drain state could not be proven. "
    "Inspect the controller/host state and the E3 event logs by hand before any retry. "
    "No automatic retry and no automatic cleanup was attempted."
)


class ConfigError(ValueError):
    """Config mapping rejected; problems are sorted constant field labels."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = sorted(set(str(problem) for problem in problems))
        super().__init__("invalid config: %s" % ", ".join(self.problems))


class E3RunnerError(RuntimeError):
    """A runner-phase invariant failed; details are constant labels only."""


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Configuration (minimal, provenance-safe shape: run_id + e3 section only).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class E3Settings:
    """Validated E3 campaign settings (fixture identifiers are not secrets)."""

    run_id: str
    target_card: str
    unrelated_card: str
    cold_card: str
    isolated_fixture: bool
    sampling_interval_s: float
    injection_window_s: float
    drain_window_s: float
    max_attempts: int
    controller_timeout_s: float
    nodes: Tuple[str, ...]
    decision_node: str

    def public_metadata(self) -> Dict[str, Any]:
        return {
            "runId": self.run_id,
            "targetCard": self.target_card,
            "unrelatedCard": self.unrelated_card,
            "coldCard": self.cold_card,
            "isolatedFixture": self.isolated_fixture,
            "samplingIntervalS": self.sampling_interval_s,
            "injectionWindowS": self.injection_window_s,
            "drainWindowS": self.drain_window_s,
            "maxAttempts": self.max_attempts,
            "controllerTimeoutS": self.controller_timeout_s,
            "nodes": list(self.nodes),
            # Logical probe alias only; scrubbed like every stored string.
            "decisionNode": e3_e4._stored(self.decision_node),
        }


def _scheduled_samples(window_s: float, interval_s: float) -> int:
    if window_s <= 0:
        return 0
    return int(math.ceil(float(window_s) / float(interval_s) - 1e-9))


def _validate_e3_section(raw: Mapping[str, Any]) -> E3Settings:
    run_id = raw.get("run_id")
    if not isinstance(run_id, str) or not experiment_common.SAFE_ID.fullmatch(run_id):
        raise ConfigError(["invalid:run_id"])
    e3 = raw.get("e3")
    if not isinstance(e3, Mapping):
        raise ConfigError(["missing:e3"])
    allowlist = e3.get("allowlist")
    if not isinstance(allowlist, Mapping):
        raise ConfigError(["missing:e3.allowlist"])
    problems: List[str] = []

    cards: Dict[str, Any] = {}
    for role in ("target_card", "unrelated_card", "cold_card"):
        value = allowlist.get(role)
        if not isinstance(value, str) or not _CARD_RE.fullmatch(value):
            problems.append("invalid:e3.allowlist.%s" % role)
        cards[role] = value
    if not problems and len(set(cards.values())) != 3:
        problems.append("invalid:e3.allowlist.cards_not_distinct")
    isolated = allowlist.get("isolated_fixture")
    if not isinstance(isolated, bool):
        problems.append("invalid:e3.allowlist.isolated_fixture")

    windows = e3.get("windows")
    if not isinstance(windows, Mapping):
        problems.append("missing:e3.windows")
        interval = None
        injection_window = None
        drain_window = None
    else:
        interval = windows.get("sampling_interval_s")
        if (
            isinstance(interval, bool)
            or not isinstance(interval, (int, float))
            or not MIN_INTERVAL_S <= float(interval) <= MAX_INTERVAL_S
        ):
            problems.append("invalid:e3.windows.sampling_interval_s")
            interval = None
        injection_window = windows.get("injection_window_s")
        drain_window = windows.get("drain_window_s")
        for name in ("injection_window_s", "drain_window_s"):
            value = windows.get(name)
            valid = (
                not isinstance(value, bool)
                and isinstance(value, (int, float))
                and 0.0 <= float(value) <= MAX_WINDOW_S
            )
            if not valid:
                problems.append("invalid:e3.windows.%s" % name)
                if name == "injection_window_s":
                    injection_window = None
                else:
                    drain_window = None
        if interval is not None and injection_window is not None:
            if _scheduled_samples(float(injection_window), float(interval)) > MAX_SAMPLES_PER_WINDOW:
                problems.append("invalid:e3.windows.injection_window_sample_bound")
        if interval is not None and drain_window is not None:
            if _scheduled_samples(float(drain_window), float(interval)) > MAX_SAMPLES_PER_WINDOW:
                problems.append("invalid:e3.windows.drain_window_sample_bound")

    bounds = e3.get("bounds")
    if not isinstance(bounds, Mapping):
        problems.append("missing:e3.bounds")
        max_attempts = None
    else:
        max_attempts = bounds.get("max_attempts")
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or not 1 <= max_attempts <= MAX_ATTEMPTS
        ):
            problems.append("invalid:e3.bounds.max_attempts")
            max_attempts = None

    nodes = e3.get("nodes")
    if (
        not isinstance(nodes, list)
        or not 1 <= len(nodes) <= MAX_NODES
        or any(not isinstance(node, str) or not node for node in nodes)
        or len(set(nodes)) != len(nodes)
    ):
        problems.append("invalid:e3.nodes")

    decision_node = e3.get("decision_node", "gateway")
    if not isinstance(decision_node, str) or not decision_node or len(decision_node) > 64:
        problems.append("invalid:e3.decision_node")

    controller_timeout = e3.get("controller_timeout_s", DEFAULT_CONTROLLER_TIMEOUT_S)
    if (
        isinstance(controller_timeout, bool)
        or not isinstance(controller_timeout, (int, float))
        or not MIN_CONTROLLER_TIMEOUT_S <= float(controller_timeout) <= MAX_CONTROLLER_TIMEOUT_S
    ):
        problems.append("invalid:e3.controller_timeout_s")
        controller_timeout = DEFAULT_CONTROLLER_TIMEOUT_S

    if problems:
        raise ConfigError(sorted(set(problems)))

    return E3Settings(
        run_id=str(run_id),
        target_card=str(cards["target_card"]),
        unrelated_card=str(cards["unrelated_card"]),
        cold_card=str(cards["cold_card"]),
        isolated_fixture=bool(isolated),
        sampling_interval_s=float(interval),
        injection_window_s=float(injection_window),
        drain_window_s=float(drain_window),
        max_attempts=int(max_attempts),
        controller_timeout_s=float(controller_timeout),
        nodes=tuple(str(node) for node in nodes),
        decision_node=str(decision_node),
    )


def load_e3_config(raw: Mapping[str, Any]) -> E3Settings:
    """Validate the minimal E3 config shape (``run_id`` + ``e3`` section)."""
    if not isinstance(raw, Mapping):
        raise ConfigError(["config_not_a_mapping"])
    return _validate_e3_section(raw)


def config_sha256(raw_config: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(raw_config, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def e3_operation_ids(run_id: str) -> Dict[str, str]:
    """Stable operation ids for the two injected phases (deterministic)."""
    return {
        "injection": stable_id(run_id, "e3:injection"),
        "drain": stable_id(run_id, "e3:drain"),
    }


# ---------------------------------------------------------------------------
# Injected primitives. This module ships NO implementation of any of these;
# the real platform controller/probe/collector primitives remain BLOCKED and
# belong to the separately gated campaign harness. Fakes may be injected for
# offline rehearsal (subject to the same live gate).
# ---------------------------------------------------------------------------


@runtime_checkable
class InjectionController(Protocol):
    """Fault-injection controller; each method is called at most once per run.

    Every method receives the stable operation id for its phase and returns
    an arbitrary ack mapping (stored scrubbed and truncated). Implementations
    must be idempotent on their side; the runner never retries a phase.
    """

    def begin_injection(self, operation_id: str) -> Mapping[str, Any]: ...

    def end_injection(self, operation_id: str) -> Mapping[str, Any]: ...

    def begin_drain(self, operation_id: str) -> Mapping[str, Any]: ...

    def end_drain(self, operation_id: str) -> Mapping[str, Any]: ...


@runtime_checkable
class E3LogCollector(Protocol):
    """Collects raw server-log lines containing E3 projector observations."""

    def collect_e3_lines(self, node: str) -> Sequence[str]: ...


@runtime_checkable
class DurableRowReader(Protocol):
    """Reads durable delta rows keyed by event id (SELECT-side only).

    The returned mapping must be ``event_id -> {"attempts": int, "status": str,
    ...}`` with statuses SUCCEEDED / QUARANTINED / PENDING / LEASED, matching
    ``experiment_common.validate_e3_attempt_history``.
    """

    def read_delta_rows(self, event_ids: Sequence[str]) -> Mapping[str, Mapping[str, Any]]: ...


@runtime_checkable
class RequestLogCollector(Protocol):
    """Collects request-side event log lines for explicit request ids."""

    def collect_request_lines(self, node: str, request_ids: Sequence[str]) -> Sequence[str]: ...


# ---------------------------------------------------------------------------
# Markers: wall + monotonic time, one per controller phase boundary.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhaseMarker:
    """One phase boundary.

    ``injection_start``/``drain_start`` are captured immediately BEFORE the
    controller call (lower bound of the true phase interval);
    ``injection_end``/``drain_end`` immediately AFTER the call returns (upper
    bound). ``ack`` is the scrubbed controller acknowledgement.
    """

    marker: str
    operation_id: str
    sequence: int
    wall_unix_ns: int
    monotonic_ns: int
    ack: Mapping[str, Any]


def _scrub_ack(ack: Any) -> Dict[str, Any]:
    if ack is None:
        return {"present": False}
    if isinstance(ack, Mapping):
        scrubbed: Dict[str, Any] = {"present": True}
        for index, (key, value) in enumerate(ack.items()):
            if index >= 8:
                scrubbed["truncated"] = True
                break
            scrubbed[str(key)[:32]] = e3_e4._stored(value)
        return scrubbed
    return {"present": True, "repr": e3_e4._stored(str(ack))}


def _controller_effect_proven(ack: Any, operation_id: str, expected_state: str) -> bool:
    """Require the hook ACK to bind this effect identity to its resulting state."""
    if not isinstance(ack, Mapping):
        return False
    returned_id = ack.get("operation_id")
    state = ack.get("state", ack.get("effect_state", ack.get("effectState")))
    return (
        ack.get("applied") is True
        and returned_id == operation_id
        and isinstance(state, str)
        and state.strip().upper() == expected_state
    )


def _require_controller_effect(
    ok: bool, ack: Any, operation_id: str, expected_state: str, phase: str
) -> Tuple[bool, Optional[str]]:
    if not ok:
        return False, None
    if not _controller_effect_proven(ack, operation_id, expected_state):
        return False, "effect_ack_unproven:%s" % phase
    return True, None


def validate_markers(
    markers: Sequence[PhaseMarker], operation_ids: Mapping[str, str]
) -> Dict[str, Any]:
    """Validate marker order, operation-id pairing, and controller effect proof.

    Each controller ACK must echo its stable operation id and the resulting
    effect state (ACTIVE/INACTIVE/DRAINING/DRAINED). ACK presence alone is not
    evidence that the intended effect occurred.

    Ordering contract: strictly increasing ``monotonic_ns`` across the four
    markers in MARKER_NAMES order, non-decreasing ``wall_unix_ns``, and
    ``injection_end <= drain_start`` on the monotonic axis.
    """
    by_name: Dict[str, PhaseMarker] = {}
    problems: List[str] = []
    for marker in markers:
        if marker.marker in by_name:
            problems.append("marker_duplicate:%s" % marker.marker)
        by_name[marker.marker] = marker
    missing = [name for name in MARKER_NAMES if name not in by_name]
    if missing:
        problems.append("markers_missing:%s" % ":".join(missing))
    ordered = [by_name[name] for name in MARKER_NAMES if name in by_name]
    for first, second in zip(ordered, ordered[1:]):
        if second.monotonic_ns <= first.monotonic_ns:
            problems.append("marker_monotonic_order_violation")
            break
    for first, second in zip(ordered, ordered[1:]):
        if second.wall_unix_ns < first.wall_unix_ns:
            problems.append("marker_wall_order_violation")
            break
    effect_problems: List[str] = []
    for name in ("injection_start", "injection_end"):
        if name in by_name:
            marker = by_name[name]
            if marker.operation_id != operation_ids["injection"]:
                problems.append("marker_operation_id_mismatch:injection")
            if not _controller_effect_proven(
                marker.ack, operation_ids["injection"], _MARKER_EFFECT_STATES[name]
            ):
                effect_problems.append("marker_effect_unproven:%s" % name)
    for name in ("drain_start", "drain_end"):
        if name in by_name:
            marker = by_name[name]
            if marker.operation_id != operation_ids["drain"]:
                problems.append("marker_operation_id_mismatch:drain")
            if not _controller_effect_proven(
                marker.ack, operation_ids["drain"], _MARKER_EFFECT_STATES[name]
            ):
                effect_problems.append("marker_effect_unproven:%s" % name)
    if not missing:
        if by_name["drain_start"].monotonic_ns < by_name["injection_end"].monotonic_ns:
            problems.append("marker_interval_overlap_violation")
    problems.extend(effect_problems)
    return {
        "complete": not missing,
        "valid": not missing and not problems,
        "missing": missing,
        "problems": sorted(set(problems)),
        "markers": [asdict(marker) for marker in markers],
    }


# ---------------------------------------------------------------------------
# Bounded dispatch: every injected call runs once, in a bounded join.
# ---------------------------------------------------------------------------


def _call_bounded(label: str, fn: Callable[[], Any], timeout_s: float) -> Tuple[bool, Any, Optional[str]]:
    """Invoke ``fn`` once with a bounded join. Never retries.

    Returns ``(ok, value, problem)``. On timeout the worker thread is left
    running as a daemon (state unknown, recorded, never rejoined).
    """
    result: Dict[str, Any] = {}

    def _target() -> None:
        try:
            result["value"] = fn()
        except BaseException as error:  # noqa: BLE001 - phase errors are recorded, not raised
            result["error"] = error

    worker = threading.Thread(target=_target, name="e3-runner-%s" % label, daemon=True)
    worker.start()
    worker.join(max(float(timeout_s), MIN_CONTROLLER_TIMEOUT_S))
    if worker.is_alive():
        return False, None, "timeout:%s" % label
    if "error" in result:
        return False, None, "error:%s:%s" % (label, type(result["error"]).__name__)
    return True, result.get("value"), None


# ---------------------------------------------------------------------------
# Streaming sampling digests (sink for e3_e4.sample_e3).
# ---------------------------------------------------------------------------


def _publication_read_success(sample: Mapping[str, Any]) -> bool:
    """Whether this snapshot contains any healthy read indicator."""
    return any(
        sample.get(section, {}).get("status") == "PASS"
        for section in ("queue_counts", "row_counts", "pointers")
    )


def _publication_drain_proven(sample: Mapping[str, Any]) -> bool:
    """Require explicit zero queue depth and worker readiness in this sample."""
    queues = sample.get("queue_counts", {})
    entries = queues.get("entries", {}) if isinstance(queues, Mapping) else {}
    queue_zero = bool(entries) and queues.get("status") == "PASS" and all(
        isinstance(entry, Mapping)
        and entry.get("status") == "PASS"
        and isinstance(entry.get("value"), int)
        and not isinstance(entry.get("value"), bool)
        and entry.get("value") == 0
        for entry in entries.values()
    )
    health = sample.get("worker_health", {})
    readiness = health.get("health_endpoint", {}) if isinstance(health, Mapping) else {}
    ready = (
        isinstance(readiness, Mapping)
        and readiness.get("status") == "PASS"
        and readiness.get("healthy") is True
    )
    return queue_zero and ready


def _section_statuses(sample: Mapping[str, Any]) -> Dict[str, Any]:
    statuses: Dict[str, Any] = {}
    for section in ("queue_counts", "row_counts", "pointers"):
        statuses[section] = sample.get(section, {}).get("status")
    health = sample.get("worker_health", {})
    if isinstance(health, Mapping) and health:
        statuses["worker_health"] = worst_status(
            str(entry.get("status")) for entry in health.values() if isinstance(entry, Mapping)
        )
    else:
        statuses["worker_health"] = "SKIP"
    return statuses


class _WindowStream:
    """Bounded streaming sink; keeps request ids, never raw response bodies."""

    def __init__(self, phase: str) -> None:
        self.phase = phase
        self.samples: List[Dict[str, Any]] = []
        self.request_ids: List[Dict[str, Any]] = []
        self.request_id_counts: Dict[str, int] = {}
        self.invalid_request_id_samples = 0
        self.truncated = False

    def __call__(self, sample: Mapping[str, Any]) -> None:
        if len(self.samples) >= MAX_SAMPLES_PER_WINDOW:
            self.truncated = True
            return
        decisions: List[Dict[str, Any]] = []
        for entry in sample.get("decisions", []):
            decisions.append(
                {
                    "role": entry.get("role"),
                    "card": entry.get("card"),
                    "decision_status": entry.get("decision_status"),
                    "classification": entry.get("classification"),
                    "http_status": entry.get("http_status"),
                    "reason": entry.get("reason"),
                    "generation": entry.get("generation"),
                    "pending_predicate": entry.get("pending_predicate"),
                    "latency_ms": entry.get("latency_ms"),
                    "request_id": entry.get("request_id"),
                    # Probe-level classification; host admission is asserted
                    # only by the separate request-side cross-check.
                    "decision_basis": "probe_level",
                }
            )
            request_id = entry.get("request_id")
            if isinstance(request_id, str) and _REQUEST_ID_RE.fullmatch(request_id):
                self.request_id_counts[request_id] = self.request_id_counts.get(request_id, 0) + 1
            else:
                self.invalid_request_id_samples += 1
            if isinstance(request_id, str) and _REQUEST_ID_RE.fullmatch(request_id) and len(self.request_ids) < 3 * MAX_SAMPLES_PER_WINDOW:
                self.request_ids.append(
                    {
                        "phase": self.phase,
                        "seq": sample.get("seq"),
                        "role": entry.get("role"),
                        "request_id": request_id,
                    }
                )
        self.samples.append(
            {
                "phase": self.phase,
                "seq": sample.get("seq"),
                "taken_at": sample.get("taken_at"),
                "probe_clock_epoch_s": sample.get("probe_clock_epoch_s"),
                "publication_read_success": _publication_read_success(sample),
                "publication_drain_proven": _publication_drain_proven(sample),
                "section_statuses": _section_statuses(sample),
                "decisions": decisions,
            }
        )


def _run_window(
    probe: Any,
    settings: E3Settings,
    sample_config: E3SampleConfig,
    phase: str,
    duration_s: float,
    wall_fn: Callable[[], int],
    problems: List[str],
) -> Tuple[Optional[Dict[str, Any]], _WindowStream, str]:
    """One fixed-interval sampling window through sample_e3 (read-only).

    Returns ``(summary, stream, outcome)`` with outcome in
    ``ran`` / ``skipped`` (duration 0) / ``failed`` (sampling raised).
    """
    stream = _WindowStream(phase)
    if duration_s <= 0:
        return None, stream, "skipped"
    try:
        summary = sample_e3(
            probe,
            settings.target_card,
            settings.unrelated_card,
            settings.cold_card,
            settings.sampling_interval_s,
            float(duration_s),
            None,
            stream,
            config=sample_config,
            decision_node=settings.decision_node,
            clock=lambda: wall_fn() / 1e9,
        )
    except Exception as error:  # noqa: BLE001 - sampling failure is recorded, never fatal
        problems.append("sampling_failed:%s:%s" % (phase, type(error).__name__))
        return None, stream, "failed"
    if summary.get("sink_errors"):
        problems.append("sink_stream_errors:%s" % phase)
    if not summary.get("completed"):
        problems.append("window_not_completed:%s" % phase)
    if stream.truncated:
        problems.append("sample_stream_truncated:%s" % phase)
    return summary, stream, "ran"


# ---------------------------------------------------------------------------
# Per-attempt evidence: collector lines -> E3 events -> durable reconciliation.
# ---------------------------------------------------------------------------


def accumulate_attempt_time_ns(events: Sequence[Any]) -> Dict[str, Any]:
    """Cumulative attempt wall time from claim->terminal pairs, per process.

    Cross-process wall clock is advisory only (no E4 clock-offset proof is
    applied here); the value is never used for a verdict.
    """
    by_epoch: Dict[Tuple[str, str], List[Any]] = {}
    for event in events:
        by_epoch.setdefault((event.node, event.process_observation_id), []).append(event)
    total_ns = 0
    paired = 0
    for _epoch, epoch_events in sorted(by_epoch.items()):
        open_claim: Optional[Any] = None
        for event in sorted(epoch_events, key=lambda item: item.sequence):
            if event.event == "enqueue_staged":
                continue
            if event.event == "claim_committed":
                open_claim = event
                continue
            if open_claim is not None and event.event in experiment_common.E3_TERMINAL_EVENTS:
                total_ns += max(0, int(event.wall_unix_ns) - int(open_claim.wall_unix_ns))
                paired += 1
                open_claim = None
    return {
        "paired_attempts": paired,
        "cumulative_attempt_wall_ns": total_ns,
        "note": "cross-process wall clock; advisory only, never verdict-bearing",
    }


def _collect_e3_events(
    collector: Any,
    settings: E3Settings,
    problems: List[str],
    limitations: List[Dict[str, Any]],
) -> Tuple[List[Any], bool]:
    """Collect and parse E3 projector events for every configured node."""
    events: List[Any] = []
    for node in settings.nodes:
        ok, lines, problem = _call_bounded(
            "collect_e3_lines:%s" % node,
            lambda node=node: collector.collect_e3_lines(node),
            settings.controller_timeout_s,
        )
        if not ok:
            problems.append(str(problem))
            continue
        try:
            events.extend(parse_e3_events(lines, node))
        except EvidenceError:
            problems.append("event_parse_error:%s" % node)
    if len(events) > MAX_E3_EVENTS:
        problems.append("event_log_bound_exceeded")
        limitations.append(
            {
                "item": "event_log_bound",
                "status": "SKIP",
                "note": "collected event count exceeded the runner bound; durable reconciliation skipped",
            }
        )
        return events, False
    return events, True


def _read_durable_rows(
    row_reader: Any,
    event_ids: Sequence[str],
    settings: E3Settings,
    problems: List[str],
    limitations: List[Dict[str, Any]],
) -> Optional[Mapping[str, Mapping[str, Any]]]:
    if len(event_ids) > MAX_EVENT_IDS:
        problems.append("event_id_bound_exceeded")
        limitations.append(
            {
                "item": "event_id_bound",
                "status": "SKIP",
                "note": "distinct event id count exceeded the runner bound; durable reconciliation skipped",
            }
        )
        return None
    ok, rows, problem = _call_bounded(
        "read_delta_rows",
        lambda: row_reader.read_delta_rows(list(event_ids)),
        settings.controller_timeout_s,
    )
    if not ok:
        problems.append(str(problem or "durable_rows_error"))
        return None
    if not isinstance(rows, Mapping):
        problems.append("durable_rows_error:unexpected_shape")
        return None
    return rows


# ---------------------------------------------------------------------------
# Host admission cross-check: probe-level decisions vs request-side logs.
# ---------------------------------------------------------------------------


def crosscheck_host_admissions(
    request_log_collector: Any,
    settings: E3Settings,
    decisions_by_request: Mapping[str, str],
    problems: List[str],
    limitations: List[Dict[str, Any]],
    *,
    invalid_request_id_samples: int = 0,
    duplicate_request_ids: Sequence[str] = (),
    sample_stream_truncated: bool = False,
) -> Dict[str, Any]:
    """Cross-check sampled request ids against request-side event logs.

    Every sampled decision must have a present, unique request id and exactly
    one matching ``decision_return``. ALLOW additionally requires exactly one
    matching ``host_admission``; non-ALLOW must have none. Malformed, duplicate,
    missing, truncated, or unpaired ids cannot PASS. Explicit contradictions
    are FAIL; incomplete evidence is UNKNOWN or BLOCKED, never inferred away.
    """
    if request_log_collector is None:
        limitations.append(
            {
                "item": "host_admission_crosscheck",
                "status": "SKIP",
                "note": "no request-log collector injected; host-admission evidence is unavailable",
            }
        )
        return {
            "status": "SKIP",
            "checked": 0,
            "confirmed": 0,
            "verifiedNonAllow": 0,
            "unverified": 0,
            "contradictions": [],
        }
    ids = list(decisions_by_request.keys())
    truncated = len(ids) > MAX_CROSSCHECK_REQUEST_IDS
    if truncated:
        ids = ids[:MAX_CROSSCHECK_REQUEST_IDS]
        limitations.append(
            {
                "item": "crosscheck_request_id_cap",
                "status": "SKIP",
                "note": "request id list truncated at the crosscheck bound",
            }
        )
    invalid_count = max(0, int(invalid_request_id_samples))
    duplicate_ids = sorted(set(str(item) for item in duplicate_request_ids))
    truncated = truncated or bool(sample_stream_truncated)
    if duplicate_ids:
        limitations.append(
            {
                "item": "duplicate_sampled_request_ids",
                "status": "SKIP",
                "note": "sampled request ids are not unique across probe calls",
            }
        )
    by_id: Dict[str, Dict[str, Any]] = {}
    parse_ok = True
    for node in settings.nodes:
        ok, lines, problem = _call_bounded(
            "collect_request_lines:%s" % node,
            lambda node=node: request_log_collector.collect_request_lines(node, ids),
            settings.controller_timeout_s,
        )
        if not ok:
            problems.append(str(problem))
            parse_ok = False
            continue
        try:
            request_events = parse_authz_events(lines, node)
        except EvidenceError:
            problems.append("crosscheck_parse_error:%s" % node)
            parse_ok = False
            continue
        for event in request_events:
            info = by_id.setdefault(
                event.request_id,
                {"events": 0, "host_admissions": [], "decision_returns": []},
            )
            info["events"] += 1
            if event.event == "host_admission":
                info["host_admissions"].append(event)
            elif event.event == "decision_return":
                info["decision_returns"].append(event)

    contradictions: List[Dict[str, Any]] = []
    confirmed = 0
    unverified_ids = 0
    verified_non_allow = 0
    if parse_ok:
        for request_id in ids:
            expected = decisions_by_request[request_id]
            info = by_id.get(request_id)
            if info is None:
                unverified_ids += 1
                continue
            decision_returns = info["decision_returns"]
            admissions = info["host_admissions"]
            if len(decision_returns) != 1:
                if len(decision_returns) > 1:
                    contradictions.append(
                        {"request_id": request_id, "kind": "duplicate_decision_return"}
                    )
                else:
                    unverified_ids += 1
                continue
            decision = decision_returns[0]
            returned_allowed = decision.fields.get("allowed")
            reason = str(decision.fields.get("reason") or "").upper()
            missing_decision_context = [
                field for field in _REQUEST_CONTEXT_FIELDS
                if decision.fields.get(field) is None or not str(decision.fields.get(field)).strip()
            ]
            if expected == "UNKNOWN" or missing_decision_context:
                unverified_ids += 1
                continue
            if expected == "ALLOW":
                if returned_allowed is not True:
                    contradictions.append(
                        {"request_id": request_id, "kind": "probe_allow_host_denial"}
                    )
                elif len(admissions) > 1:
                    contradictions.append(
                        {"request_id": request_id, "kind": "duplicate_host_admission"}
                    )
                elif len(admissions) == 1:
                    admission = admissions[0]
                    admission_missing_context = [
                        field for field in _REQUEST_CONTEXT_FIELDS
                        if admission.fields.get(field) is None
                        or not str(admission.fields.get(field)).strip()
                    ]
                    context_mismatches = [
                        field for field in _REQUEST_CONTEXT_FIELDS
                        if admission.fields.get(field) != decision.fields.get(field)
                    ]
                    if (
                        admission.node != decision.node
                        or admission.process_observation_id != decision.process_observation_id
                        or admission.sequence <= decision.sequence
                        or admission_missing_context
                        or context_mismatches
                    ):
                        contradictions.append(
                            {
                                "request_id": request_id,
                                "kind": "host_admission_identity_order_or_context_mismatch",
                                "missing_context": admission_missing_context,
                                "context_mismatches": context_mismatches,
                            }
                        )
                    else:
                        confirmed += 1
                else:
                    unverified_ids += 1
            else:
                pending_reason = "AUTHORIZATION_PENDING" in reason
                if returned_allowed is True or admissions:
                    contradictions.append(
                        {"request_id": request_id, "kind": "probe_non_admission_with_host_admission"}
                    )
                elif not isinstance(returned_allowed, bool):
                    unverified_ids += 1
                elif not reason:
                    unverified_ids += 1
                elif (expected == "PENDING") != pending_reason:
                    contradictions.append(
                        {"request_id": request_id, "kind": "probe_host_decision_reason_mismatch"}
                    )
                else:
                    verified_non_allow += 1
        if contradictions:
            problems.append("probe_host_decision_contradiction")
    incomplete = bool(invalid_count or duplicate_ids or truncated or unverified_ids or not ids)
    if incomplete:
        limitations.append(
            {
                "item": "crosscheck_incomplete_request_ids",
                "status": "SKIP",
                "note": (
                    "host admission is not a full PASS with invalid=%d duplicate=%d unverified=%d truncated=%s"
                    % (invalid_count, len(duplicate_ids), unverified_ids, truncated)
                ),
            }
        )
    if contradictions:
        status = "FAIL"
    elif not parse_ok:
        status = "UNKNOWN"
    elif incomplete:
        status = "UNKNOWN" if ids or invalid_count or duplicate_ids or truncated else "BLOCKED"
    elif confirmed + verified_non_allow != len(ids):
        status = "UNKNOWN"
    else:
        status = "PASS"
    return {
        "status": status,
        "checked": len(ids),
        "confirmed": confirmed,
        "verifiedNonAllow": verified_non_allow,
        "unverified": unverified_ids,
        "invalidRequestIdSamples": invalid_count,
        "duplicateRequestIds": duplicate_ids,
        "truncated": truncated,
        "contradictions": contradictions,
        "decision_basis": "host_admission_from_request_side_event_logs",
    }


# ---------------------------------------------------------------------------
# The four protocol E3 output categories.
# ---------------------------------------------------------------------------


def _decisions_for_role(streams: Sequence[Optional[_WindowStream]], role: str) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    for stream in streams:
        if stream is None:
            continue
        for digest in stream.samples:
            for decision in digest["decisions"]:
                if decision.get("role") == role:
                    selected.append(decision)
    return selected


def build_output_categories(
    stream_injection: Optional[_WindowStream],
    stream_drain: Optional[_WindowStream],
    per_event: Mapping[str, Any],
    *,
    host_crosscheck: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Compute the four E3 output categories from sampling + per-event state."""
    streams = (stream_injection, stream_drain)
    target = _decisions_for_role(streams, "target")
    unrelated = _decisions_for_role(streams, "unrelated")
    cold = _decisions_for_role(streams, "cold")
    drain_samples = list(stream_drain.samples) if stream_drain is not None else []
    injection_samples = list(stream_injection.samples) if stream_injection is not None else []
    per_status = str(per_event.get("status") or "BLOCKED")
    publication_drain_proven = bool(
        drain_samples
        and per_status == "PASS"
        and all(digest.get("publication_drain_proven") is True for digest in drain_samples)
    )

    host_status = str((host_crosscheck or {}).get("status") or "BLOCKED")
    target_identities = {
        (decision.get("phase"), decision.get("seq"))
        for stream in streams if stream is not None
        for digest in stream.samples
        for decision in digest["decisions"]
        if decision.get("role") == "target"
    }
    target_crosschecked = bool(target_identities) and host_status == "PASS"
    if not target:
        request_side = {"status": "SKIP", "note": "no target-card decision samples collected"}
    elif all(decision.get("decision_status") == "BLOCKED" for decision in target):
        request_side = {
            "status": "BLOCKED",
            "note": "actor-aware probe required; target decisions never executed",
        }
    elif any(decision.get("classification") in {"PENDING", "DENY"} for decision in target):
        request_side = {
            "status": "PASS" if target_crosschecked else "UNKNOWN",
            "note": (
                "probe-level target pending/denial observed and every request id reconciled"
                if target_crosschecked else
                "probe-level target pending/denial observed, but host-admission request evidence is incomplete"
            ),
            "decision_basis": "probe_level_plus_request_side_crosscheck" if target_crosschecked else "probe_level_unconfirmed",
        }
    else:
        request_side = {
            "status": "SKIP",
            "note": "no probe-level target pending/denial observed; workload-level trigger absent",
        }

    if not unrelated:
        unrelated_category: Dict[str, Any] = {
            "status": "SKIP",
            "note": "no unrelated-card decision samples collected",
        }
    elif all(decision.get("decision_status") == "BLOCKED" for decision in unrelated):
        unrelated_category = {
            "status": "BLOCKED",
            "note": "actor-aware probe required; unrelated decisions never executed",
        }
    elif any(decision.get("classification") == "ALLOW" for decision in unrelated):
        unrelated_category = {
            "status": "PASS",
            "note": "probe-level unrelated-card ALLOW observed (probe-level, not host admission)",
            "decision_basis": "probe_level",
        }
    elif any(decision.get("classification") == "UNKNOWN" for decision in unrelated):
        unrelated_category = {
            "status": "UNKNOWN",
            "note": "unrelated-card availability inconclusive at probe level",
        }
    else:
        unrelated_category = {
            "status": "UNKNOWN",
            "note": "no probe-level ALLOW on the unrelated card; availability not demonstrated",
        }
    unrelated_category["cold"] = {
        "samples": len(cold),
        "allowObserved": any(decision.get("classification") == "ALLOW" for decision in cold),
    }

    if not drain_samples:
        publication = {
            "status": "SKIP",
            "note": "drain window produced no samples; publication drain not observed",
        }
    elif publication_drain_proven:
        publication = {
            "status": "PASS",
            "note": "every drain sample proves zero queue depth and ready worker; matching per-event history is terminal and reconciled",
        }
    elif any(digest["publication_read_success"] for digest in drain_samples):
        publication = {
            "status": "UNKNOWN",
            "note": (
                "successful snapshot reads prove observability only; unless every drain sample "
                "proves zero queue depth plus worker readiness and matching durable terminal "
                "history, publication drain remains unproven"
            ),
        }
    elif any(
        status in {"UNKNOWN", "BLOCKED"}
        for digest in drain_samples
        for status in digest["section_statuses"].values()
    ):
        publication = {
            "status": "UNKNOWN",
            "note": "publication indicators configured but failed/unavailable in the drain window",
        }
    else:
        publication = {
            "status": "SKIP",
            "note": "publication indicators not configured or not observed",
        }

    per_event_category: Dict[str, Any] = {
        "status": per_status,
        "events": per_event.get("events"),
        "attempts": per_event.get("attempts"),
        "note": "durable per-attempt history from injected collector + row reconciliation",
    }
    unknown_reasons = per_event.get("unknown")
    if isinstance(unknown_reasons, list) and unknown_reasons:
        per_event_category["unknownReasons"] = [str(reason) for reason in unknown_reasons[:5]]

    return {
        CATEGORY_REQUEST_SIDE: request_side,
        CATEGORY_UNRELATED: unrelated_category,
        CATEGORY_PUBLICATION: publication,
        CATEGORY_PER_EVENT: per_event_category,
    }


# ---------------------------------------------------------------------------
# Live gate (Exec-L3): approval + allowlist + isolated fixture + opt-in.
# ---------------------------------------------------------------------------


def _check_live_gate(
    allow_live_execution: bool,
    approval_ref: Optional[str],
    approval_record: Any,
    settings: E3Settings,
) -> Optional[str]:
    """Return a block reason when the live gate is not fully satisfied."""
    if not allow_live_execution:
        return "live_not_enabled"
    if not isinstance(approval_ref, str) or not APPROVAL_REF_RE.fullmatch(approval_ref):
        return "approval_ref_missing_or_unsafe"
    record: Any = approval_record
    if isinstance(record, (str, Path)):
        try:
            record = json.loads(Path(record).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            return "approval_record_unreadable:%s" % type(error).__name__
    if not isinstance(record, Mapping):
        return "approval_record_not_a_mapping"
    if record.get("run_id") != settings.run_id:
        return "approval_record_run_id_mismatch"
    if record.get("approval_ref") != approval_ref:
        return "approval_record_ref_mismatch"
    approved_by = record.get("approved_by")
    if not isinstance(approved_by, str) or not approved_by.strip():
        return "approval_record_approver_missing"
    if not settings.isolated_fixture:
        return "fixture_not_isolated"
    return None


# ---------------------------------------------------------------------------
# Evidence freezing (local artifact writes only).
# ---------------------------------------------------------------------------


def _freeze(out_dir: Path, manifest: Mapping[str, Any], artifacts: Sequence[Path]) -> Dict[str, Any]:
    atomic_json(out_dir / "manifest.json", manifest)
    paths = [out_dir / "manifest.json"] + list(artifacts)
    write_checksums(out_dir, paths)
    return dict(manifest)


def _write_window_artifact(
    out_dir: Path, stream: Optional[_WindowStream], summary: Optional[Mapping[str, Any]], window: str
) -> Optional[str]:
    if stream is None or not stream.samples:
        return None
    name = "e3-samples-%s.json" % window
    payload = {
        "kind": "e3_sampling_digest",
        "window": window,
        "generated_at": _utc_now_iso(),
        "summary": summary,
        "sample_count": len(stream.samples),
        "request_id_count": len(stream.request_ids),
        "stream_truncated": stream.truncated,
        "samples": stream.samples,
        "request_ids": stream.request_ids,
    }
    atomic_json(out_dir / name, payload)
    return name


# ---------------------------------------------------------------------------
# Entry point: the campaign. Live side effects require the full gate.
# ---------------------------------------------------------------------------


def execute_campaign(
    raw_config: Mapping[str, Any],
    out_dir: Path,
    *,
    probe: Any = None,
    controller: Any = None,
    collector: Any = None,
    row_reader: Any = None,
    request_log_collector: Any = None,
    sample_config: Optional[E3SampleConfig] = None,
    allow_live_execution: bool = False,
    approval_ref: Optional[str] = None,
    approval_record: Any = None,
    approval_validator: Optional[Callable[[str, str, str], bool]] = None,
    wall_clock: Optional[Callable[[], int]] = None,
    mono_clock: Optional[Callable[[], int]] = None,
) -> Dict[str, Any]:
    """Run the E3 recovery-tail orchestration.

    ``probe`` must satisfy the ``e3_e4`` actor-aware read-only probe contract
    (``sql``/``redis``/``signed_get_for_role``). ``controller`` implements the
    four injection/drain phase methods. ``collector``/``row_reader``/
    ``request_log_collector`` are optional; without them the corresponding
    evidence categories degrade to BLOCKED/UNKNOWN and a full claim is
    impossible. Every controller phase is attempted at most once.

    Nothing is constructed or called before the live gate passes; on any
    gate or primitive failure the manifest is BLOCKED with constant problem
    labels and no further I/O happens beyond the local evidence write.
    """
    settings = load_e3_config(raw_config)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    wall_fn = wall_clock if wall_clock is not None else time.time_ns
    mono_fn = mono_clock if mono_clock is not None else time.monotonic_ns
    sample_config = sample_config if sample_config is not None else E3SampleConfig()
    operation_ids = e3_operation_ids(settings.run_id)

    manifest: Dict[str, Any] = {
        "kind": "e3_recovery_tail",
        "experiment": "E3",
        "mode": "campaign",
        "campaignId": settings.run_id,
        "status": "BLOCKED",
        "generated_at": _utc_now_iso(),
        "settings": settings.public_metadata(),
        "configSha256": config_sha256(raw_config),
        "operationIds": dict(operation_ids),
        "problems": [],
        "phaseFailures": [],
        "markers": [],
        "sampling": {},
        "outputCategories": {},
        "perEventRetryHistory": None,
        "hostAdmissionCrosscheck": None,
        "attemptTime": None,
        "e3_evidence_claim": E3_CLAIM_NONE,
        "status_note": None,
        "manual_reconciliation_required": False,
        "injection_may_still_be_active": False,
        "drain_may_still_be_active": False,
        "controller_state_unknown": False,
        "reconciliation_prompt": None,
        "limitations": [],
    }
    problems: List[str] = manifest["problems"]
    limitations: List[Dict[str, Any]] = manifest["limitations"]

    # -- Live gate FIRST: no probe/controller call may happen before this.
    gate_problem = _check_live_gate(allow_live_execution, approval_ref, approval_record, settings)
    if gate_problem is not None:
        problems.append(gate_problem)
        return _freeze(out_dir, manifest, [])
    if approval_validator is None:
        problems.append("independent_user_approval_not_verified")
        return _freeze(out_dir, manifest, [])
    try:
        approval_verified = approval_validator(
            settings.run_id, str(approval_ref), config_sha256(raw_config)
        )
    except Exception:
        approval_verified = False
    if approval_verified is not True:
        problems.append("independent_user_approval_not_verified")
        return _freeze(out_dir, manifest, [])

    # -- Injected primitive availability (pure checks; nothing constructed).
    if probe is None:
        problems.append("missing_probe")
    if controller is None:
        problems.append("missing_injection_controller")
    if probe is None or controller is None:
        limitations.append(
            {
                "item": "real_platform_primitives",
                "status": "BLOCKED",
                "note": (
                    "this module ships no real probe/controller/collector; the platform "
                    "primitives are injected by the separately gated campaign harness "
                    "(fakes may be injected for offline rehearsal, subject to the same gate)"
                ),
            }
        )
        return _freeze(out_dir, manifest, [])

    markers: List[PhaseMarker] = []
    phase_failures: List[Dict[str, Any]] = manifest["phaseFailures"]
    abort_reason: Optional[str] = None
    injection_may_be_active = False
    drain_may_be_active = False

    # -- Phase 1: begin_injection (marker captured BEFORE the call).
    ok, ack, problem = _call_bounded(
        "begin_injection",
        lambda: controller.begin_injection(operation_ids["injection"]),
        settings.controller_timeout_s,
    )
    ok, effect_problem = _require_controller_effect(
        ok, ack, operation_ids["injection"], "ACTIVE", "begin_injection"
    )
    problem = effect_problem or problem
    if ok:
        markers.append(
            PhaseMarker(
                "injection_start",
                operation_ids["injection"],
                1,
                int(wall_fn()),
                int(mono_fn()),
                _scrub_ack(ack),
            )
        )
    else:
        phase_failures.append(
            {
                "phase": "begin_injection",
                "problem": problem,
                "controller_state_unknown": True,
                "injection_may_be_active": True,
            }
        )
        problems.append("controller_phase_failure:begin_injection")
        injection_may_be_active = (effect_problem is not None)
        abort_reason = "begin_injection"

    summary_injection: Optional[Dict[str, Any]] = None
    stream_injection: Optional[_WindowStream] = None
    outcome_injection = "skipped"
    summary_drain: Optional[Dict[str, Any]] = None
    stream_drain: Optional[_WindowStream] = None
    outcome_drain = "skipped"

    if abort_reason is None:
        summary_injection, stream_injection, outcome_injection = _run_window(
            probe,
            settings,
            sample_config,
            "injection",
            settings.injection_window_s,
            wall_fn,
            problems,
        )
        # end_injection is always attempted once once begin succeeded: leaving
        # the injected fault active is worse than a degraded sample window.
        ok, ack, problem = _call_bounded(
            "end_injection",
            lambda: controller.end_injection(operation_ids["injection"]),
            settings.controller_timeout_s,
        )
        ok, effect_problem = _require_controller_effect(
            ok, ack, operation_ids["injection"], "INACTIVE", "end_injection"
        )
        problem = effect_problem or problem
        if ok:
            markers.append(
                PhaseMarker(
                    "injection_end",
                    operation_ids["injection"],
                    2,
                    int(wall_fn()),
                    int(mono_fn()),
                    _scrub_ack(ack),
                )
            )
        else:
            phase_failures.append(
                {
                    "phase": "end_injection",
                    "problem": problem,
                    "controller_state_unknown": True,
                    "injection_may_still_be_active": True,
                }
            )
            problems.append("controller_phase_failure:end_injection")
            injection_may_be_active = True
            abort_reason = "end_injection"

    if abort_reason is None:
        ok, ack, problem = _call_bounded(
            "begin_drain",
            lambda: controller.begin_drain(operation_ids["drain"]),
            settings.controller_timeout_s,
        )
        ok, effect_problem = _require_controller_effect(
            ok, ack, operation_ids["drain"], "DRAINING", "begin_drain"
        )
        problem = effect_problem or problem
        if ok:
            markers.append(
                PhaseMarker(
                    "drain_start",
                    operation_ids["drain"],
                    3,
                    int(wall_fn()),
                    int(mono_fn()),
                    _scrub_ack(ack),
                )
            )
            summary_drain, stream_drain, outcome_drain = _run_window(
                probe,
                settings,
                sample_config,
                "drain",
                settings.drain_window_s,
                wall_fn,
                problems,
            )
            ok, ack, problem = _call_bounded(
                "end_drain",
                lambda: controller.end_drain(operation_ids["drain"]),
                settings.controller_timeout_s,
            )
            ok, effect_problem = _require_controller_effect(
                ok, ack, operation_ids["drain"], "DRAINED", "end_drain"
            )
            problem = effect_problem or problem
            if ok:
                markers.append(
                    PhaseMarker(
                        "drain_end",
                        operation_ids["drain"],
                        4,
                        int(wall_fn()),
                        int(mono_fn()),
                        _scrub_ack(ack),
                    )
                )
            else:
                phase_failures.append(
                    {
                        "phase": "end_drain",
                        "problem": problem,
                        "controller_state_unknown": True,
                        "drain_may_still_be_active": True,
                    }
                )
                problems.append("controller_phase_failure:end_drain")
                drain_may_be_active = True
                abort_reason = "end_drain"
        else:
            phase_failures.append(
                {
                    "phase": "begin_drain",
                    "problem": problem,
                    "controller_state_unknown": True,
                }
            )
            problems.append("controller_phase_failure:begin_drain")
            abort_reason = "begin_drain"

    marker_report = validate_markers(markers, operation_ids)
    manifest["markers"] = marker_report["markers"]
    problems.extend(marker_report["problems"])
    drain_completed = marker_report["complete"] and abort_reason is None
    if not drain_completed:
        problems.append("drain_not_completed")

    # -- Post-drain per-attempt evidence (only after a completed drain).
    per_event: Dict[str, Any]
    events: List[Any] = []
    collection_ok = True
    if not drain_completed:
        # The drain never completed (controller abort): the per-attempt gate
        # was never reached, which is recorded SKIP here; the abort itself
        # keeps the overall verdict at UNKNOWN via the phase-failure pool.
        per_event = {
            "status": "SKIP",
            "note": "drain_not_completed_after_abort:%s" % (abort_reason or "markers_incomplete"),
            "events": 0,
            "attempts": 0,
            "perEvent": {},
            "unknown": [],
        }
    else:
        if collector is None:
            limitations.append(
                {
                    "item": "e3_event_log",
                    "status": "BLOCKED",
                    "note": "no e3 log collector injected; per-attempt history cannot be validated",
                }
            )
            collection_ok = False
        else:
            events, collection_ok = _collect_e3_events(collector, settings, problems, limitations)
        durable_rows: Optional[Mapping[str, Mapping[str, Any]]] = None
        reconciliation_ready = False
        if collection_ok and events:
            event_ids = sorted({event.event_id for event in events})
            if row_reader is None:
                limitations.append(
                    {
                        "item": "durable_row_reconciliation",
                        "status": "BLOCKED",
                        "note": "no durable row reader injected; exact durable reconciliation impossible, PASS prevented",
                    }
                )
            else:
                durable_rows = _read_durable_rows(
                    row_reader, event_ids, settings, problems, limitations
                )
                reconciliation_ready = durable_rows is not None
        report = validate_e3_attempt_history(events, durable_rows)
        if report.get("status") == "PASS" and not reconciliation_ready:
            # Never certify PASS without exact durable reconciliation.
            report = dict(report)
            report["status"] = "BLOCKED"
            report["unknown"] = list(report.get("unknown", [])) + [
                "durable_row_reconciliation_unavailable"
            ]
            report["note"] = "per-attempt logs parsed but durable rows were not reconciled"
        bound_exceeded: List[str] = []
        for delta_id, entry in report.get("perEvent", {}).items():
            last_attempt = entry.get("lastAttempt") if isinstance(entry, Mapping) else None
            if isinstance(last_attempt, int) and last_attempt > settings.max_attempts:
                bound_exceeded.append(str(delta_id))
        if bound_exceeded:
            problems.append("attempt_bound_exceeded")
            report = dict(report)
            report["status"] = "UNKNOWN"
            report["attemptBoundExceeded"] = sorted(set(bound_exceeded))
        per_event = report
    manifest["perEventRetryHistory"] = per_event
    if events:
        manifest["attemptTime"] = accumulate_attempt_time_ns(events)

    # -- Probe-level decision vs host admission cross-check.
    decisions_by_request: Dict[str, str] = {}
    for stream in (stream_injection, stream_drain):
        if stream is None:
            continue
        for digest in stream.samples:
            for decision in digest["decisions"]:
                request_id = decision.get("request_id")
                classification = decision.get("classification")
                if request_id and classification in {"ALLOW", "PENDING", "DENY", "UNKNOWN"}:
                    decisions_by_request.setdefault(str(request_id), str(classification))

    request_id_counts: Dict[str, int] = {}
    invalid_request_id_samples = 0
    sample_stream_truncated = False
    for stream in (stream_injection, stream_drain):
        if stream is None:
            continue
        invalid_request_id_samples += stream.invalid_request_id_samples
        sample_stream_truncated = sample_stream_truncated or stream.truncated
        for request_id, count in stream.request_id_counts.items():
            request_id_counts[request_id] = request_id_counts.get(request_id, 0) + count
    duplicate_request_ids = sorted(
        request_id for request_id, count in request_id_counts.items() if count > 1
    )
    crosscheck = crosscheck_host_admissions(
        request_log_collector,
        settings,
        decisions_by_request,
        problems,
        limitations,
        invalid_request_id_samples=invalid_request_id_samples,
        duplicate_request_ids=duplicate_request_ids,
        sample_stream_truncated=sample_stream_truncated,
    )
    manifest["hostAdmissionCrosscheck"] = crosscheck

    categories = build_output_categories(
        stream_injection, stream_drain, per_event, host_crosscheck=crosscheck
    )
    manifest["outputCategories"] = categories

    # -- Sampling artifacts (bounded digests with retained request ids).
    artifact_injection = _write_window_artifact(out_dir, stream_injection, summary_injection, "injection")
    artifact_drain = _write_window_artifact(out_dir, stream_drain, summary_drain, "drain")
    manifest["sampling"] = {
        "injection_window": {
            "outcome": outcome_injection,
            "summary": summary_injection,
            "sampleCount": len(stream_injection.samples) if stream_injection else 0,
            "requestIdCount": len(stream_injection.request_ids) if stream_injection else 0,
            "artifact": artifact_injection,
        },
        "drain_window": {
            "outcome": outcome_drain,
            "summary": summary_drain,
            "sampleCount": len(stream_drain.samples) if stream_drain else 0,
            "requestIdCount": len(stream_drain.request_ids) if stream_drain else 0,
            "artifact": artifact_drain,
        },
    }

    # -- Overall verdict: worst of every executed evidence stream. PASS can
    # only emerge when every category, window, marker, and reconciliation
    # stream is PASS; any problem floors the verdict to UNKNOWN.
    pool: List[str] = []
    for outcome, summary in ((outcome_injection, summary_injection), (outcome_drain, summary_drain)):
        if outcome == "ran" and summary is not None:
            pool.append(str(summary.get("overall")))
        elif outcome == "skipped" and abort_reason is not None:
            pool.append("UNKNOWN")
        elif outcome == "skipped":
            pool.append("SKIP")
        else:
            pool.append("UNKNOWN")
    pool.append(str(per_event.get("status") or "BLOCKED"))
    pool.extend(str(category.get("status") or "UNKNOWN") for category in categories.values())
    if not marker_report["valid"]:
        pool.append("UNKNOWN")
    pool.append(str(crosscheck.get("status") or "UNKNOWN"))
    if phase_failures:
        pool.append("UNKNOWN")
    if problems:
        pool.append("UNKNOWN")
    if request_log_collector is None and categories[CATEGORY_REQUEST_SIDE]["status"] == "SKIP":
        pool.remove("SKIP")
        pool.append("UNKNOWN")
    overall = worst_status(pool)
    manifest["status"] = overall

    manual_reconciliation = bool(phase_failures) or not marker_report["valid"] or any(
        problem.startswith(
            (
                "sampling_failed",
                "sink_stream_errors",
                "window_not_completed",
                "durable_rows_error",
                "event_parse_error",
                "timeout:",
            )
        )
        for problem in problems
    ) or per_event.get("status") == "UNKNOWN"
    manifest["manual_reconciliation_required"] = bool(manual_reconciliation)
    manifest["injection_may_still_be_active"] = injection_may_be_active
    manifest["drain_may_still_be_active"] = drain_may_be_active
    manifest["controller_state_unknown"] = any(
        failure.get("controller_state_unknown") for failure in phase_failures
    )
    if manual_reconciliation:
        manifest["reconciliation_prompt"] = RECONCILIATION_PROMPT

    if overall == "PASS":
        manifest["e3_evidence_claim"] = E3_CLAIM_FULL
        manifest["status_note"] = (
            "complete recovery-tail claim: all four output categories, durable per-attempt "
            "reconciliation, complete marker intervals, and host-admission cross-check"
        )
    else:
        manifest["e3_evidence_claim"] = E3_CLAIM_NONE
        manifest["status_note"] = (
            "E3 evidence incomplete or unproven; the maximum supported claim is the weaker "
            "workload-level recovery-tail conclusion (protocol E3)"
        )

    artifacts = [out_dir / name for name in (artifact_injection, artifact_drain) if name]
    return _freeze(out_dir, manifest, artifacts)


# ---------------------------------------------------------------------------
# Entry point: offline plan. No primitive is constructed; nothing is contacted.
# ---------------------------------------------------------------------------


def execute_plan(raw_config: Mapping[str, Any], out_dir: Path) -> Dict[str, Any]:
    """Offline planning: validates config, writes plan.json + checksums."""
    settings = load_e3_config(raw_config)
    out_dir = Path(out_dir)
    plan: Dict[str, Any] = {
        "kind": "e3_recovery_tail",
        "experiment": "E3",
        "mode": "plan",
        "status": "PLANNED",
        "campaignId": settings.run_id,
        "generated_at": _utc_now_iso(),
        "settings": settings.public_metadata(),
        "configSha256": config_sha256(raw_config),
        "operationIds": e3_operation_ids(settings.run_id),
        "phases": [
            {
                "phase": "injection",
                "markers": ["injection_start", "injection_end"],
                "samplingWindowS": settings.injection_window_s,
                "dispatchBudget": 1,
            },
            {
                "phase": "drain",
                "markers": ["drain_start", "drain_end"],
                "samplingWindowS": settings.drain_window_s,
                "dispatchBudget": 1,
            },
        ],
        "markerContract": {
            "timeSources": ["wall_unix_ns", "monotonic_ns"],
            "ordering": (
                "strictly increasing monotonic_ns across injection_start, injection_end, "
                "drain_start, drain_end; non-decreasing wall_unix_ns; injection_end <= drain_start"
            ),
            "capturePoint": "start markers pre-call, end markers post-call",
        },
        "bounds": {
            "minIntervalS": MIN_INTERVAL_S,
            "maxIntervalS": MAX_INTERVAL_S,
            "maxWindowS": MAX_WINDOW_S,
            "maxSamplesPerWindow": MAX_SAMPLES_PER_WINDOW,
            "maxAttempts": MAX_ATTEMPTS,
            "maxEventIds": MAX_EVENT_IDS,
            "maxCrosscheckRequestIds": MAX_CROSSCHECK_REQUEST_IDS,
        },
        "gateRequirements": [
            "allow_live_execution",
            "approval_ref",
            "approval_record(run_id, approval_ref, approved_by)",
            "independent approval_validator(run_id, approval_ref, config_sha256) == True",
            "e3.allowlist.isolated_fixture",
            "injected probe",
            "injected injection controller",
        ],
        "injectedPrimitives": [
            "probe (e3_e4 actor-aware read-only probe)",
            "injection controller (four phase methods, called at most once each)",
            "e3 log collector (optional; per-attempt category BLOCKED without it)",
            "durable row reader (optional; PASS prevented without it)",
            "request log collector (optional; host admission stays unconfirmed without it)",
        ],
        "outputCategories": list(OUTPUT_CATEGORIES),
        "evidenceContract": {
            "fullClaim": E3_CLAIM_FULL,
            "fullClaimRequires": [
                "all four output categories PASS",
                "durable per-attempt reconciliation",
                "complete ordered marker intervals",
                "host-admission cross-check PASS",
                "no problems or phase failures",
            ],
            "otherwise": E3_CLAIM_NONE,
        },
        "livePrimitiveStatus": "BLOCKED",
        "livePrimitiveNote": (
            "no real controller/probe ships in this module; a bare CLI run --live is always "
            "BLOCKED. Live mutation/fault injection is a future Exec-L3 action."
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    atomic_json(out_dir / "plan.json", plan)
    write_checksums(out_dir, [out_dir / "plan.json"])
    return plan


# ---------------------------------------------------------------------------
# CLI. Default mode 'plan' is offline and never contacts anything.
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="e3_runner.py",
        description=(
            "E3 recovery-tail campaign runner. Default mode 'plan' is offline and never "
            "contacts anything. 'run' performs the gated campaign; without injected "
            "primitives (library API only) it stays BLOCKED -- the real platform "
            "injection controller is a future Exec-L3 primitive and is never reachable "
            "from this CLI."
        ),
    )
    parser.add_argument("mode", nargs="?", choices=("plan", "run"), default="plan")
    parser.add_argument("--config", required=True, help="path to the E3 config JSON")
    parser.add_argument("--out", default="e3_out", help="evidence output directory")
    parser.add_argument(
        "--live",
        action="store_true",
        help="opt-in to the gated campaign (run mode only); BLOCKED without injected primitives",
    )
    parser.add_argument(
        "--approval-ref",
        default=None,
        help="explicit caller-supplied approval reference (required with --live)",
    )
    parser.add_argument(
        "--approval-record",
        default=None,
        help="path to the external approval record JSON (required with --live)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        raw_config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print("config_unreadable:%s" % type(error).__name__, file=sys.stderr)
        return 2
    if not isinstance(raw_config, Mapping):
        print("config_not_a_mapping", file=sys.stderr)
        return 2
    out_dir = Path(args.out)
    try:
        if args.mode == "plan":
            result = execute_plan(raw_config, out_dir)
        elif not args.live:
            # 'run' without --live stays fully offline: no primitive is
            # constructed and nothing is contacted.
            settings = load_e3_config(raw_config)
            result = {
                "kind": "e3_recovery_tail",
                "experiment": "E3",
                "mode": "run",
                "campaignId": settings.run_id,
                "status": "BLOCKED",
                "problems": ["live_not_enabled"],
                "settings": settings.public_metadata(),
                "configSha256": config_sha256(raw_config),
                "generated_at": _utc_now_iso(),
            }
            out_dir.mkdir(parents=True, exist_ok=True)
            atomic_json(out_dir / "manifest.json", result)
            write_checksums(out_dir, [out_dir / "manifest.json"])
        else:
            # Even with --live and a full approval record, this CLI cannot
            # inject the probe/controller primitives, so the campaign is
            # BLOCKED by design (real platform primitive remains BLOCKED).
            result = execute_campaign(
                raw_config,
                out_dir,
                allow_live_execution=True,
                approval_ref=args.approval_ref,
                approval_record=args.approval_record,
            )
    except ConfigError as error:
        print("blocked:%s" % error, file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "mode": result.get("mode"),
                "campaignId": result.get("campaignId"),
                "status": result.get("status"),
                "claim": result.get("e3_evidence_claim"),
            },
            sort_keys=True,
        )
    )
    return 0 if result.get("status") in {"PASS", "PLANNED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
