#!/usr/bin/env python3
"""Read-only E3/E4 evidence helpers for the authorization validation campaign.

Scope and safety boundary (Exec-L1):

- This module performs NO I/O of its own. Every external read goes through an
  injected :class:`ReadOnlyProbe` supplied by the caller; without a probe the
  module cannot reach any service, database, or network endpoint.
- All SQL this module issues is asserted SELECT-only before execution
  (:func:`_require_select_only`); Redis verbs are restricted to ``LLEN``/``GET``
  ``PING``; the HTTP surface is limited to read-only signed GETs. The module
  performs no mutation, no fault injection, no writes, and never starts or
  stops any service.
- No credentials and no hostnames are embedded in returned data. Node
  identities are replaced by ``node-<index>`` aliases, and every probe-derived
  string is scrubbed for host-like tokens (IP literals, scheme URLs, domain
  names) and truncated before it is stored.
- Unprovable preconditions are reported ``BLOCKED``/``UNKNOWN``/``SKIP`` and
  never collapse into ``PASS`` (AGENTS.md section 7.1 semantics).

Validation mapping (Docs/authorization-validation/VALIDATION_PROTOCOL.md):

- ``capture_e4_preconditions`` -- E4 deployment preconditions: MySQL
  transaction isolation, ``read_only``/``super_read_only``, session time zone,
  UTC clock offset, and the cache-generation epoch
  (``astral:auth:cache_epoch``, see astral-db/src/cache_epoch.rs).
- ``sample_e3`` -- E3 recovery-tail snapshot sampling: fixed-interval read-only
  samples of durable delta/outbox row counts, Redis pointers/watermarks,
  queue depths, worker liveness, and per-card signed decisions
  (target / unrelated / cold-start) against the actual protected endpoint
  family (``/main/api/v1/*``). Snapshot sampling is explicitly NOT complete
  E3 evidence; see the ``limitations`` field of every summary.
- ``evaluate_fault_outcomes`` -- pure validator for E4 fault-matrix fixtures
  (redis unavailable, stale HMAC, pointer movement, worker restart, lease
  expiry, unknown ACK). Accepts only ``PENDING``/``DENY`` with a reason code;
  rejects ``ALLOW``, ``UNKNOWN``, absent outcomes, and missing reason codes.

Python 3.8+ standard library only. Offline unit tests live in
``test_e3_e4.py`` next to this file and use in-memory fake probes only.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    runtime_checkable,
)

__all__ = [
    "ALLOWED_STATUSES",
    "E3SampleConfig",
    "ReadOnlyProbe",
    "ActorAwareReadOnlyProbe",
    "ClockSamplingProbe",
    "capture_e4_preconditions",
    "sample_e3",
    "evaluate_fault_outcomes",
    "main",
]

# ---------------------------------------------------------------------------
# Statuses (aligned with tools/experiment_common.py ALLOWED_STATUSES and
# AGENTS.md section 7.1 evidence-status semantics).
# ---------------------------------------------------------------------------

ALLOWED_STATUSES = {"PASS", "FAIL", "BLOCKED", "UNKNOWN", "PENDING", "SKIP", "PLANNED"}

# Worst-first ranking used to aggregate check statuses into an overall status.
# FAIL (proven violation) outranks BLOCKED (not proven); an empty set is
# treated as BLOCKED because nothing was proven.
_STATUS_RANK = {"FAIL": 0, "BLOCKED": 1, "UNKNOWN": 2, "PENDING": 3, "SKIP": 4, "PASS": 5}


def _worst_status(statuses: Iterable[str]) -> str:
    """Aggregate statuses into the worst one; an empty set is BLOCKED."""
    status_list = list(statuses)
    if not status_list:
        return "BLOCKED"
    return min(status_list, key=lambda status: _STATUS_RANK.get(status, _STATUS_RANK["UNKNOWN"]))


# ---------------------------------------------------------------------------
# Scrubbing: no hosts, no secrets, bounded strings in returned data.
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOSTNAME_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|io|dev|app|local|internal|lan|example|test|invalid)\b",
    re.IGNORECASE,
)

_SCRUB_REPLACEMENT = "[redacted-host]"
_STORED_STRING_LIMIT = 120
_REASON_LIMIT = 200


def _scrub_text(value: str) -> str:
    """Redact host-like tokens from a probe-derived string."""
    scrubbed = _URL_RE.sub(_SCRUB_REPLACEMENT, value)
    scrubbed = _IPV4_RE.sub(_SCRUB_REPLACEMENT, scrubbed)
    scrubbed = _HOSTNAME_RE.sub(_SCRUB_REPLACEMENT, scrubbed)
    return scrubbed


def _stored(value: Any, limit: int = _STORED_STRING_LIMIT) -> Any:
    """Coerce a probe-derived scalar for storage: scrub, truncate, bound type."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _scrub_text(str(value))[:limit]


# ---------------------------------------------------------------------------
# SELECT-only guard for every SQL statement this module issues.
# ---------------------------------------------------------------------------

_LINE_COMMENT_RE = re.compile(r"--[^\n]*|#[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _require_select_only(query: str) -> str:
    """Validate that ``query`` is a single SELECT statement; return it intact.

    Conservative by design: any statement separator beyond one trailing
    semicolon is rejected even inside string literals. Non-SELECT input is a
    caller programming error and raises immediately, before any probe call.
    """
    if not isinstance(query, str) or not query.strip():
        raise ValueError("SQL statement must be a non-empty string")
    stripped = _BLOCK_COMMENT_RE.sub(" ", _LINE_COMMENT_RE.sub(" ", query)).strip()
    if not stripped.upper().startswith("SELECT"):
        raise ValueError("only SELECT statements are permitted (read-only probe contract)")
    body = stripped[:-1] if stripped.endswith(";") else stripped
    if ";" in body:
        raise ValueError("multiple SQL statements are not permitted")
    return query


def _sql_scalar(probe: Any, query: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Run one SELECT and extract a single scalar cell.

    Returns ``(value, problem, error_class)``; exactly one of ``value`` /
    ``problem`` is None. Problems are constant labels (never raw error text,
    which could contain hostnames or credentials).
    """
    try:
        rows = probe.sql(query)
    except Exception as error:  # noqa: BLE001 - probe errors must not escape
        return None, "sql_error", type(error).__name__
    if not isinstance(rows, list):
        return None, "unexpected_result_shape", None
    if len(rows) == 0:
        return None, "empty_result", None
    if len(rows) != 1 or len(rows[0]) != 1:
        return None, "ambiguous_result", None
    value = rows[0][0]
    if value is None:
        return None, "null_value", None
    return str(value), None, None


# ---------------------------------------------------------------------------
# Probe contracts. The module never opens sockets or connections itself.
# ---------------------------------------------------------------------------


@runtime_checkable
class ReadOnlyProbe(Protocol):
    """Minimal read-only probe surface injected by the campaign harness.

    Implementations must be strictly read-only:

    - ``sql(query)`` executes one read-only SQL statement (SELECT) and returns
      the result table as a list of rows of string cells.
    - ``redis(*argv)`` executes one read-only Redis command (the module only
      ever sends ``LLEN``, ``GET``, ``PING``) and returns the bulk reply as
      ``str`` (empty string for a missing key).
    - ``signed_get(node, path)`` performs one signed read-only HTTP GET
      against the protected endpoint on the given logical node and returns
      ``(http_status, body_dict[, request_id])``. This legacy method is used
      for worker health only. Per-card decisions require the actor-aware
      extension below.
    """

    def sql(self, query: str) -> List[List[str]]: ...

    def redis(self, *argv: str) -> str: ...

    def signed_get(self, node: str, path: str) -> Tuple[Any, ...]: ...


@runtime_checkable
class ActorAwareReadOnlyProbe(ReadOnlyProbe, Protocol):
    """Role-specific signed GET with a verified card binding and request id."""

    def signed_get_for_role(
        self, role: str, card: str, node: str, path: str
    ) -> Tuple[int, Dict[str, Any], str]: ...


@runtime_checkable
class ClockSamplingProbe(ReadOnlyProbe, Protocol):
    """Optional probe extension exposing the probe host wall clock.

    ``clock_sample()`` returns seconds since the UNIX epoch (float) as seen by
    the probe host. When a probe does not implement it, the module falls back
    to the local clock, which must then be UTC-synchronized for the E4 skew
    check to be meaningful.
    """

    def clock_sample(self) -> float: ...


def _clock_fn(probe: Any, clock: Optional[Callable[[], float]]) -> Callable[[], float]:
    """Resolve the clock source: explicit override, probe, then local time."""
    if clock is not None:
        return clock
    probe_clock = getattr(probe, "clock_sample", None)
    if callable(probe_clock):
        return probe_clock
    return time.time


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# E4: deployment preconditions capture (read-only).
# ---------------------------------------------------------------------------

#: Real cache-generation epoch key (astral-db/src/cache_epoch.rs).
#: The value is a random UUID written with SET NX; rotation is DEL + re-SETNX.
DEFAULT_CACHE_EPOCH_KEY = "astral:auth:cache_epoch"

#: |UTC_TIMESTAMP() - probe clock| tolerated before the offset check fails.
#: MySQL UTC_TIMESTAMP has one-second resolution, so 2s absorbs rounding.
DEFAULT_CLOCK_SKEW_THRESHOLD_S = 2.0

_KNOWN_ISOLATIONS = {"READ-UNCOMMITTED", "READ-COMMITTED", "REPEATABLE-READ", "SERIALIZABLE"}

_ISOLATION_QUERY_MYSQL8 = "SELECT @@global.transaction_isolation"
_ISOLATION_QUERY_MYSQL57 = "SELECT @@global.tx_isolation"
_READ_ONLY_QUERY = "SELECT @@global.read_only"
_SUPER_READ_ONLY_QUERY = "SELECT @@global.super_read_only"
_SESSION_TZ_QUERY = "SELECT @@session.time_zone"
_UTC_NOW_QUERY = "SELECT UTC_TIMESTAMP()"


def _scalar_check(
    probe: Any,
    primary: str,
    fallback: Optional[str],
    validate: Callable[[str], str],
    fallback_probe: Any = None,
) -> Dict[str, Any]:
    """Capture one scalar MySQL fact, with an optional fallback query."""
    target = fallback_probe if (fallback_probe is not None and fallback) else probe
    value, problem, error_class = _sql_scalar(target, primary)
    used_query = primary
    if problem is not None and fallback:
        value, problem, error_class = _sql_scalar(target, fallback)
        used_query = fallback
    if problem is not None:
        entry: Dict[str, Any] = {"status": "UNKNOWN", "note": problem}
        if error_class:
            entry["error_class"] = error_class
        return entry
    status = validate(value)
    entry = {"status": status, "value": _stored(value), "query": used_query}
    if status != "PASS":
        entry["note"] = "value failed form validation"
    return entry


def _validate_isolation(value: str) -> str:
    normalized = value.strip().upper().replace(" ", "-").replace("_", "-")
    return "PASS" if normalized in _KNOWN_ISOLATIONS else "UNKNOWN"


def _validate_flag(value: str) -> str:
    return "PASS" if value.strip() in {"0", "1"} else "UNKNOWN"


def _validate_time_zone(value: str) -> str:
    return "PASS" if value.strip() else "UNKNOWN"


def _capture_utc_clock(
    probe: Any,
    clock_fn: Callable[[], float],
    threshold_s: float,
) -> Dict[str, Any]:
    """Compare MySQL UTC_TIMESTAMP() against the probe clock."""
    value, problem, error_class = _sql_scalar(probe, _UTC_NOW_QUERY)
    if problem is not None:
        entry: Dict[str, Any] = {"status": "UNKNOWN", "note": problem}
        if error_class:
            entry["error_class"] = error_class
        return entry
    try:
        probe_epoch = float(clock_fn())
    except Exception as error:  # noqa: BLE001
        return {"status": "UNKNOWN", "note": "clock_unavailable", "error_class": type(error).__name__}
    try:
        db_dt = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return {"status": "UNKNOWN", "note": "unparseable_utc_timestamp", "value": _stored(value)}
    db_epoch = db_dt.timestamp()
    skew_s = round(db_epoch - probe_epoch, 3)
    status = "PASS" if abs(skew_s) <= threshold_s else "FAIL"
    return {
        "status": status,
        "value": {"db_utc": value.strip(), "probe_epoch_s": round(probe_epoch, 3), "skew_s": skew_s},
        "threshold_s": threshold_s,
        "query": _UTC_NOW_QUERY,
    }


def _capture_cache_epoch(
    probe: Any,
    cache_epoch_key: str,
    cache_epoch_query: Optional[str],
) -> Dict[str, Any]:
    """Read the cache-generation epoch from Redis (or SQL when configured).

    The epoch value is expected to be an opaque non-empty token (a random UUID
    in the current implementation), not a monotonically increasing integer.
    """
    if cache_epoch_query is not None:
        _require_select_only(cache_epoch_query)
        value, problem, error_class = _sql_scalar(probe, cache_epoch_query)
        entry: Dict[str, Any] = {"source": "sql"}
        if problem is not None:
            entry["status"] = "UNKNOWN"
            entry["note"] = problem
            if error_class:
                entry["error_class"] = error_class
            return entry
        entry["status"] = "PASS" if value.strip() else "UNKNOWN"
        entry["value"] = _stored(value)
        entry["query"] = cache_epoch_query
        return entry
    if not cache_epoch_key:
        return {"status": "SKIP", "source": "redis-GET", "note": "no cache_epoch_key configured"}
    if not hasattr(probe, "redis"):
        return {
            "status": "BLOCKED",
            "source": "redis-GET",
            "note": "probe lacks redis capability and no cache_epoch_query was configured",
        }
    try:
        raw = probe.redis("GET", cache_epoch_key)
    except Exception as error:  # noqa: BLE001
        return {
            "status": "UNKNOWN",
            "source": "redis-GET",
            "note": "redis_error",
            "error_class": type(error).__name__,
        }
    text = "" if raw is None else str(raw).strip()
    if not text or text.lower() == "nil":
        return {
            "status": "SKIP",
            "source": "redis-GET",
            "key": cache_epoch_key,
            "note": "cache epoch key absent; epoch not yet initialized",
        }
    return {"status": "PASS", "source": "redis-GET", "key": cache_epoch_key, "value": _stored(text)}


def capture_e4_preconditions(
    probe: Any,
    nodes: Sequence[str],
    *,
    clock_skew_threshold_s: float = DEFAULT_CLOCK_SKEW_THRESHOLD_S,
    cache_epoch_key: str = DEFAULT_CACHE_EPOCH_KEY,
    cache_epoch_query: Optional[str] = None,
    clock: Optional[Callable[[], float]] = None,
) -> Dict[str, Any]:
    """Capture E4 deployment preconditions for each node (read-only).

    ``nodes`` entries are opaque, non-sensitive node identifiers used only for
    probe calls. They are NEVER copied into the report: results are keyed by
    ``node-<index>`` in input order. Per node the function captures:

    - MySQL ``@@global.transaction_isolation`` (with 5.7 ``tx_isolation``
      fallback),
    - ``@@global.read_only`` and ``@@global.super_read_only``,
    - ``@@session.time_zone``,
    - ``UTC_TIMESTAMP()`` versus the probe clock (offset must be within
      ``clock_skew_threshold_s`` or the check FAILs),
    - the cache-generation epoch (Redis ``GET astral:auth:cache_epoch`` by
      default, or ``cache_epoch_query`` when configured).

    Any check that cannot be proven yields ``UNKNOWN`` (probe error, empty or
    ambiguous result), ``SKIP`` (not configured), or ``BLOCKED`` (required
    probe capability missing) and prevents an overall ``PASS``. The clock
    skew check FAILs beyond the threshold. No policy expectation (for example
    which isolation level the campaign requires) is asserted here; the value
    is recorded for the campaign to assert. The function never injects faults
    and never writes anything.
    """
    if isinstance(nodes, str) or not isinstance(nodes, Sequence):
        raise TypeError("nodes must be a sequence of opaque node identifier strings")
    clock_fn = _clock_fn(probe, clock)
    node_reports: List[Dict[str, Any]] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, str) or not node:
            raise TypeError(f"nodes[{index}] must be a non-empty string")
        checks = {
            "transaction_isolation": _scalar_check(
                probe, _ISOLATION_QUERY_MYSQL8, _ISOLATION_QUERY_MYSQL57, _validate_isolation
            ),
            "read_only": _scalar_check(probe, _READ_ONLY_QUERY, None, _validate_flag),
            "super_read_only": _scalar_check(probe, _SUPER_READ_ONLY_QUERY, None, _validate_flag),
            "session_time_zone": _scalar_check(probe, _SESSION_TZ_QUERY, None, _validate_time_zone),
            "utc_clock_offset": _capture_utc_clock(probe, clock_fn, clock_skew_threshold_s),
        }
        node_reports.append(
            {
                "node_key": f"node-{index}",
                "overall": _worst_status(check["status"] for check in checks.values()),
                "checks": checks,
            }
        )
    cache_epoch = _capture_cache_epoch(probe, cache_epoch_key, cache_epoch_query)
    overall = _worst_status(
        [node["overall"] for node in node_reports] + [cache_epoch["status"]]
    )
    return {
        "kind": "e4_preconditions",
        "generated_at": _utc_now_iso(),
        "node_count": len(node_reports),
        "nodes": node_reports,
        "cache_epoch": cache_epoch,
        "overall": overall,
        "assertions": {
            "clock_skew_threshold_s": clock_skew_threshold_s,
            "note": (
                "read_only/super_read_only/isolation values are recorded and form-validated; "
                "campaign policy expectations are asserted separately against these records"
            ),
        },
        "limitations": [
            {
                "item": "pooled_connection_primary_route",
                "status": "SKIP",
                "note": (
                    "per pooled connection primary route is not observable through the read-only "
                    "probe surface; capture via server-side SHOW PROCESSLIST or pool instrumentation"
                ),
            },
            {
                "item": "cache_epoch_rotation_history",
                "status": "SKIP",
                "note": (
                    "only the current epoch value is observable read-only; initialization/rotation "
                    "history and reasons require the deployment audit log"
                ),
            },
            {
                "item": "fault_matrix",
                "status": "SKIP",
                "note": (
                    "redis unavailable / stale HMAC / pointer movement / worker restart / lease "
                    "expiry / unknown ACK outcomes are validated by evaluate_fault_outcomes on "
                    "recorded fixtures; this capture never injects faults"
                ),
            },
        ],
    }


# ---------------------------------------------------------------------------
# E3: fixed-interval read-only snapshot sampling.
# ---------------------------------------------------------------------------

#: Protected endpoint family: TrustGraph permission-check middleware intercepts
#: every request under /main/api/v1/* and maps method + path to a permission
#: decision (astral-trustgraph/src/api/permission_check.rs).
#: The campaign must confirm the exact protected path and card binding.
DEFAULT_DECISION_PATH = "/main/api/v1/permission-rules/check?resourceType=monitor&actionCode=read"

#: Grounded default row queries: durable delta/outbox and projection current
#: row counts (real tables in astral-db). Campaigns should
#: extend these with status-scoped queries.
DEFAULT_ROW_QUERIES: Tuple[Tuple[str, str], ...] = (
    ("delta_event_rows", "SELECT COUNT(*) FROM authorization_delta_event"),
    ("projection_current_rows", "SELECT COUNT(*) FROM authorization_projection_current"),
    ("archive_outbox_rows", "SELECT COUNT(*) FROM authorization_archive_outbox"),
)

#: Grounded default pointer keys: the cache-generation epoch doubles as the
#: generation pointer observable through Redis.
DEFAULT_POINTER_KEYS: Tuple[str, ...] = ("astral:auth:cache_epoch",)

#: Redis commands this module may send. Nothing else is ever transmitted.
READONLY_REDIS_VERBS = frozenset({"LLEN", "GET", "PING"})

_STOP_POLL_S = 0.02


@dataclass(frozen=True)
class E3SampleConfig:
    """Campaign-specific read targets for :func:`sample_e3`.

    All defaults are grounded in the current standalone Rust workspace implementation
    and are strictly read-only. Pass an explicit config to scope or extend.
    """

    row_queries: Tuple[Tuple[str, str], ...] = DEFAULT_ROW_QUERIES
    pointer_keys: Tuple[str, ...] = DEFAULT_POINTER_KEYS
    redis_queue_keys: Tuple[str, ...] = ()
    decision_path: str = DEFAULT_DECISION_PATH
    decision_query_param: str = "cardId"
    worker_health_path: Optional[str] = None


_CARD_ROLES: Tuple[Tuple[str, int], ...] = (("target", 0), ("unrelated", 1), ("cold", 2))


def _percent_encode(value: str) -> str:
    unreserved = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
    )
    out: List[str] = []
    for char in value:
        if char in unreserved:
            out.append(char)
        else:
            for byte in char.encode("utf-8"):
                out.append("%%%02X" % byte)
    return "".join(out)


def _decision_path_for(base_path: str, card: str, param: str) -> str:
    separator = "&" if "?" in base_path else "?"
    encoded = _percent_encode(card)
    return f"{base_path}{separator}{param}={encoded}&card_id={encoded}"


def _decision_fields(body: Any) -> Tuple[Any, str, Any]:
    """Read either a narrow legacy fixture or the real ApiResponse envelope."""
    if not isinstance(body, Mapping):
        return None, "", None
    data = body.get("data")
    data = data if isinstance(data, Mapping) else {}
    effect = data.get("effect")
    allowed = body.get("allowed")
    if isinstance(effect, str):
        allowed = effect.upper() == "ALLOW" if effect.upper() in {"ALLOW", "DENY"} else None
    reason = str(
        data.get("reason")
        or body.get("reasonCode")
        or body.get("reason")
        or ""
    )
    generation = data.get(
        "generation",
        data.get("evidenceGeneration", body.get("generation", body.get("evidence_generation"))),
    )
    return allowed, reason, generation


def _classify_decision(http_status: Any, body: Any) -> str:
    """Classify a signed decision response.

    Mirrors tools/experiment_common.py ``validate_request_terminal`` semantics
    at probe level (the separate host_admission event is not observable here):

    - 200 + body.allowed is True -> ALLOW (probe-level; confirm against
      request-side event logs before reporting a final ALLOW),
    - 401/403/503 -> PENDING only when reason contains AUTHORIZATION_PENDING,
      DENY for 401/403 when body.allowed is False, otherwise UNKNOWN,
    - anything else -> UNKNOWN.
    """
    allowed, reason, _generation = _decision_fields(body)
    if http_status == 200:
        if "AUTHORIZATION_PENDING" in reason.upper():
            return "PENDING"
        if allowed is True:
            return "ALLOW"
        if allowed is False:
            return "DENY"
        if isinstance(body, Mapping) and isinstance(body.get("data"), Mapping):
            if body["data"].get("effect") == "NO_MATCH":
                return "DENY"
        return "UNKNOWN"
    if http_status in (401, 403, 503):
        if "AUTHORIZATION_PENDING" in reason.upper():
            return "PENDING"
        if http_status in (401, 403) and allowed is False:
            return "DENY"
        if http_status in (401, 403) and isinstance(body, Mapping) and body.get("errorType") == "PERMISSION_DENIED":
            return "DENY"
        return "UNKNOWN"
    return "UNKNOWN"


def _validate_e3_config(config: E3SampleConfig) -> None:
    if not isinstance(config.decision_path, str) or not config.decision_path.startswith("/"):
        raise ValueError("decision_path must be an absolute path starting with '/'")
    seen_names = set()
    for name, query in config.row_queries:
        _require_select_only(query)
        if not isinstance(name, str) or not name:
            raise ValueError("row_queries entries need non-empty names")
        if name in seen_names:
            raise ValueError(f"duplicate row query name: {name}")
        seen_names.add(name)
    for key in config.pointer_keys:
        if not isinstance(key, str) or not key:
            raise ValueError("pointer_keys entries must be non-empty strings")
    for key in config.redis_queue_keys:
        if not isinstance(key, str) or not key:
            raise ValueError("redis_queue_keys entries must be non-empty strings")
    if config.worker_health_path is not None:
        if not isinstance(config.worker_health_path, str) or not config.worker_health_path.startswith("/"):
            raise ValueError("worker_health_path must be None or an absolute path starting with '/'")


def _redis_read(probe: Any, verb: str, *args: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """One read-only Redis command. Returns (value, problem, error_class)."""
    if verb not in READONLY_REDIS_VERBS:
        raise ValueError(f"redis verb {verb} is outside the read-only allowlist")
    if not hasattr(probe, "redis"):
        return None, "probe_lacks_redis_capability", None
    try:
        raw = probe.redis(verb, *args)
    except Exception as error:  # noqa: BLE001
        return None, "redis_error", type(error).__name__
    if raw is None:
        return None, "redis_returned_none", None
    return str(raw), None, None


def _read_queue_depths(probe: Any, config: E3SampleConfig) -> Dict[str, Any]:
    if not config.redis_queue_keys:
        return {"status": "SKIP", "note": "no redis_queue_keys configured", "entries": {}}
    entries: Dict[str, Any] = {}
    for key in config.redis_queue_keys:
        value, problem, error_class = _redis_read(probe, "LLEN", key)
        if problem is None:
            try:
                entries[key] = {"status": "PASS", "value": int(value.strip())}
            except ValueError:
                entries[key] = {
                    "status": "UNKNOWN",
                    "note": "non-integer queue depth",
                    "value": _stored(value),
                }
        else:
            entry: Dict[str, Any] = {"status": "BLOCKED" if problem == "probe_lacks_redis_capability" else "UNKNOWN", "note": problem}
            if error_class:
                entry["error_class"] = error_class
            entries[key] = entry
    return {"status": _worst_status(e["status"] for e in entries.values()), "entries": entries}


def _read_row_counts(probe: Any, config: E3SampleConfig) -> Dict[str, Any]:
    if not config.row_queries:
        return {"status": "SKIP", "note": "no row_queries configured", "entries": {}}
    entries: Dict[str, Any] = {}
    for name, query in config.row_queries:
        value, problem, error_class = _sql_scalar(probe, _require_select_only(query))
        if problem is None:
            try:
                entries[name] = {"status": "PASS", "value": int(value.strip()), "query": query}
            except ValueError:
                entries[name] = {
                    "status": "UNKNOWN",
                    "note": "non-integer row count",
                    "value": _stored(value),
                    "query": query,
                }
        else:
            entry: Dict[str, Any] = {"status": "UNKNOWN", "note": problem, "query": query}
            if error_class:
                entry["error_class"] = error_class
            entries[name] = entry
    return {"status": _worst_status(e["status"] for e in entries.values()), "entries": entries}


def _read_pointers(probe: Any, config: E3SampleConfig) -> Dict[str, Any]:
    if not config.pointer_keys:
        return {"status": "SKIP", "note": "no pointer_keys configured", "entries": {}}
    entries: Dict[str, Any] = {}
    for key in config.pointer_keys:
        value, problem, error_class = _redis_read(probe, "GET", key)
        if problem is None:
            text = value.strip()
            if text and text.lower() != "nil":
                entries[key] = {"status": "PASS", "value": _stored(text)}
            else:
                entries[key] = {"status": "UNKNOWN", "note": "pointer key absent", "key": key}
        else:
            entry: Dict[str, Any] = {"status": "BLOCKED" if problem == "probe_lacks_redis_capability" else "UNKNOWN", "note": problem}
            if error_class:
                entry["error_class"] = error_class
            entries[key] = entry
    return {"status": _worst_status(e["status"] for e in entries.values()), "entries": entries}


def _read_decisions(
    probe: Any,
    config: E3SampleConfig,
    cards: Sequence[Tuple[str, str]],
    decision_node: str,
) -> List[Dict[str, Any]]:
    """One actor-bound signed decision sample per card role."""
    results: List[Dict[str, Any]] = []
    role_get = getattr(probe, "signed_get_for_role", None)
    for role, card in cards:
        entry: Dict[str, Any] = {
            "role": role,
            "card": _stored(card),
            "endpoint": config.decision_path,
        }
        if not callable(role_get):
            entry.update({"decision_status": "BLOCKED", "note": "actor_aware_probe_required"})
            results.append(entry)
            continue
        path = _decision_path_for(config.decision_path, card, config.decision_query_param)
        started = time.monotonic()
        try:
            response = role_get(role, card, decision_node, path)
            if not isinstance(response, tuple) or len(response) != 3:
                raise ValueError("actor-aware response requires status/body/request id")
            http_status, body, request_id = response
            if not isinstance(request_id, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}", request_id
            ):
                raise ValueError("actor-aware request id invalid")
        except Exception as error:  # noqa: BLE001
            entry.update(
                {
                    "decision_status": "UNKNOWN",
                    "error_class": type(error).__name__,
                    "latency_ms": round((time.monotonic() - started) * 1000.0, 3),
                }
            )
            results.append(entry)
            continue
        latency_ms = round((time.monotonic() - started) * 1000.0, 3)
        classification = _classify_decision(http_status, body)
        _allowed, raw_reason, raw_generation = _decision_fields(body)
        reason = _stored(raw_reason, _REASON_LIMIT) if raw_reason else None
        generation = _stored(raw_generation) if raw_generation is not None else None
        entry.update(
            {
                "decision_status": "PASS" if classification != "UNKNOWN" else "UNKNOWN",
                "http_status": int(http_status) if isinstance(http_status, int) else None,
                "classification": classification,
                "reason": reason,
                "generation": generation,
                "pending_predicate": "AUTHORIZATION_PENDING" in raw_reason.upper(),
                "latency_ms": latency_ms,
                "request_id": _stored(request_id, 64),
            }
        )
        results.append(entry)
    return results


def _read_worker_health(probe: Any, config: E3SampleConfig, decision_node: str) -> Dict[str, Any]:
    health: Dict[str, Any] = {}
    value, problem, error_class = _redis_read(probe, "PING")
    if problem is None:
        pong = value.strip().upper() == "PONG"
        health["redis_ping"] = {
            "status": "PASS" if pong else "UNKNOWN",
            "healthy": pong,
            "note": None if pong else "unexpected PING reply",
            "reply": None if pong else _stored(value),
        }
    else:
        health["redis_ping"] = {
            "status": "BLOCKED" if problem == "probe_lacks_redis_capability" else "UNKNOWN",
            "healthy": None,
            "note": problem,
            "error_class": error_class,
        }
    if config.worker_health_path is None:
        health["health_endpoint"] = {"status": "SKIP", "note": "worker_health_path not configured"}
    elif not hasattr(probe, "signed_get"):
        health["health_endpoint"] = {
            "status": "BLOCKED",
            "healthy": None,
            "note": "probe lacks signed_get capability",
        }
    else:
        try:
            response = probe.signed_get(decision_node, config.worker_health_path)
            if not isinstance(response, tuple) or len(response) not in (2, 3):
                raise ValueError("worker health response shape invalid")
            http_status = response[0]
        except Exception as error:  # noqa: BLE001
            health["health_endpoint"] = {
                "status": "UNKNOWN",
                "healthy": False,
                "error_class": type(error).__name__,
            }
        else:
            healthy = isinstance(http_status, int) and 200 <= http_status < 300
            health["health_endpoint"] = {
                "status": "PASS" if healthy else "UNKNOWN",
                "healthy": healthy,
                "http_status": int(http_status) if isinstance(http_status, int) else None,
            }
    return health


def _take_e3_sample(
    probe: Any,
    config: E3SampleConfig,
    seq: int,
    cards: Sequence[Tuple[str, str]],
    decision_node: str,
    clock_fn: Callable[[], float],
) -> Dict[str, Any]:
    sample: Dict[str, Any] = {
        "seq": seq,
        "taken_at": _utc_now_iso(),
        "probe_clock_epoch_s": None,
        "queue_counts": _read_queue_depths(probe, config),
        "row_counts": _read_row_counts(probe, config),
        "pointers": _read_pointers(probe, config),
        "decisions": _read_decisions(probe, config, cards, decision_node),
        "worker_health": _read_worker_health(probe, config, decision_node),
    }
    try:
        sample["probe_clock_epoch_s"] = round(float(clock_fn()), 6)
    except Exception:  # noqa: BLE001 - clock is advisory metadata
        pass
    return sample


def _sample_entry_statuses(sample: Dict[str, Any]) -> List[str]:
    """Collect every status recorded inside one sample for aggregation."""
    statuses: List[str] = []
    for section in ("queue_counts", "row_counts", "pointers"):
        statuses.append(sample[section]["status"])
        statuses.extend(entry["status"] for entry in sample[section]["entries"].values())
    statuses.extend(decision["decision_status"] for decision in sample["decisions"])
    statuses.extend(health["status"] for health in sample["worker_health"].values())
    return statuses


def _e3_limitations(config: E3SampleConfig, probe: Any) -> List[Dict[str, Any]]:
    limitations: List[Dict[str, Any]] = [
        {
            "item": "per_attempt_decision_history",
            "status": "SKIP",
            "note": (
                "fixed-interval snapshots cannot reconstruct per-delta enqueue/claim/attempt/"
                "backoff/lease/quarantine/terminal history; per-event retry history must come "
                "from the durable per-attempt event log, so this output supports only the "
                "weaker workload-level recovery-tail conclusion"
            ),
        },
        {
            "item": "fault_injection",
            "status": "SKIP",
            "note": "this module never injects faults; injection timing and controls belong to the campaign harness",
        },
        {
            "item": "response_bodies",
            "status": "SKIP",
            "note": "only HTTP status and an allowlist of decision fields are recorded; bodies are not captured",
        },
        {
            "item": "host_admission_cross_check",
            "status": "SKIP",
            "note": (
                "ALLOW classification is probe-level (HTTP 200 with allowed=true); the "
                "host_admission cross-check must be performed against request-side event logs"
            ),
        },
        {
            "item": "worker_readiness",
            "status": "SKIP",
            "note": (
                "Redis PING proves transport liveness only; readiness must come from the "
                "deployment readiness endpoint (configure worker_health_path to record it)"
            ),
        },
    ]
    if not hasattr(probe, "redis"):
        limitations.append(
            {
                "item": "redis_reads",
                "status": "BLOCKED",
                "note": "probe exposes no redis capability; queue depths, pointers, and PING are BLOCKED",
            }
        )
    if not config.redis_queue_keys:
        limitations.append({"item": "queue_counts", "status": "SKIP", "note": "no redis_queue_keys configured"})
    if not config.pointer_keys:
        limitations.append({"item": "pointer_reads", "status": "SKIP", "note": "no pointer_keys configured"})
    if not config.row_queries:
        limitations.append({"item": "row_counts", "status": "SKIP", "note": "no row_queries configured"})
    return limitations


def sample_e3(
    probe: Any,
    target_card: str,
    unrelated_card: str,
    cold_card: str,
    interval: float,
    duration: float,
    stop_event: Any = None,
    sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    *,
    config: Optional[E3SampleConfig] = None,
    decision_node: str = "gateway",
    clock: Optional[Callable[[], float]] = None,
) -> Dict[str, Any]:
    """Sample E3 recovery-tail indicators at a fixed interval (read-only).

    Every sample captures, through the injected probe only:

    - durable queue/row counts (SELECT COUNT(*) over delta/outbox tables and
      optional Redis ``LLEN`` depths),
    - Redis pointer/watermark/generation values (``GET``),
    - per-card signed decisions for ``target_card`` (same aggregate),
      ``unrelated_card`` and ``cold_card`` via the actual protected endpoint
      (``signed_get`` against ``/main/api/v1/*``), with decision, reason code,
      evidence generation, pending predicate and measured latency,
    - worker health (Redis ``PING`` liveness; readiness endpoint when
      ``config.worker_health_path`` is set).

    ``stop_event`` (a ``threading.Event``-like object with ``is_set``/``wait``)
    stops the loop between samples; ``sink`` receives every sample as soon as
    it is taken (streaming mode keeps no copies in memory; without a sink the
    samples are returned in ``summary["samples"]``).

    This is snapshot sampling only. The summary always states
    ``e3_evidence_claim == "NOT_CLAIMED"`` and records the structural
    limitation that no reliable per-attempt decision history exists in these
    snapshots (status SKIP): a complete E3 claim requires the per-attempt
    event log and must never be based on this module's output alone.
    """
    if not isinstance(interval, (int, float)) or not math.isfinite(float(interval)) or interval <= 0:
        raise ValueError("interval must be a positive finite number of seconds")
    if not isinstance(duration, (int, float)) or not math.isfinite(float(duration)) or duration < 0:
        raise ValueError("duration must be a non-negative finite number of seconds")
    for name, card in (("target_card", target_card), ("unrelated_card", unrelated_card), ("cold_card", cold_card)):
        if not isinstance(card, str) or not card:
            raise TypeError(f"{name} must be a non-empty card identifier string")
    if not isinstance(decision_node, str) or not decision_node:
        raise ValueError("decision_node must be a non-empty logical node alias")
    if stop_event is not None and not (hasattr(stop_event, "is_set") and hasattr(stop_event, "wait")):
        raise TypeError("stop_event must provide is_set() and wait(timeout)")
    if sink is not None and not callable(sink):
        raise TypeError("sink must be callable or None")

    config = config if config is not None else E3SampleConfig()
    _validate_e3_config(config)
    cards = (("target", target_card), ("unrelated", unrelated_card), ("cold", cold_card))
    clock_fn = _clock_fn(probe, clock)

    start_mono = time.monotonic()
    deadline_mono = start_mono + float(duration)
    scheduled = int(math.ceil(float(duration) / float(interval) - 1e-9)) if duration > 0 else 0
    collected = 0
    retained: List[Dict[str, Any]] = []
    sink_errors = 0
    stopped_early = False
    entry_statuses: List[str] = []
    saw_target_decision = False
    saw_unrelated_decision = False
    saw_publication_pass = False

    while True:
        if stop_event is not None and stop_event.is_set():
            stopped_early = True
            break
        if time.monotonic() >= deadline_mono:
            break
        sample = _take_e3_sample(probe, config, collected, cards, decision_node, clock_fn)
        collected += 1
        entry_statuses.extend(_sample_entry_statuses(sample))
        for decision in sample["decisions"]:
            if decision["decision_status"] == "PASS":
                if decision["role"] == "target" and decision.get("classification") in {"PENDING", "DENY"}:
                    saw_target_decision = True
                elif decision["role"] == "unrelated" and decision.get("classification") == "ALLOW":
                    saw_unrelated_decision = True
        saw_publication_pass = saw_publication_pass or any(
            sample[section]["status"] == "PASS"
            for section in ("queue_counts", "row_counts", "pointers")
        )
        if sink is None:
            retained.append(sample)
        else:
            try:
                sink(sample)
            except Exception as error:  # noqa: BLE001 - a bad sink must not abort sampling
                sink_errors += 1
        next_tick = start_mono + collected * float(interval)
        stopped_in_wait = False
        while True:
            remaining = next_tick - time.monotonic()
            if remaining <= 0:
                break
            if stop_event is not None:
                if stop_event.wait(min(remaining, _STOP_POLL_S)):
                    stopped_in_wait = True
                    break
            else:
                time.sleep(min(remaining, _STOP_POLL_S))
        if stopped_in_wait:
            stopped_early = True
            break

    if collected == 0:
        overall = "BLOCKED"
    else:
        # SKIP entries are "not executed by design" (unconfigured optional
        # sections); they are reported in limitations/categories and must not
        # drag executed reads down, nor be promoted to PASS. With no executed
        # read at all, _worst_status([]) yields BLOCKED.
        executed = [status for status in entry_statuses if status != "SKIP"]
        overall = _worst_status(executed)
        if stopped_early:
            overall = _worst_status([overall, "UNKNOWN"])

    categories = {
        "request_side_denial_pending": {
            "status": "PASS" if saw_target_decision else "SKIP",
            "note": "target-card signed decision samples",
        },
        "unrelated_card_availability": {
            "status": "PASS" if saw_unrelated_decision else "SKIP",
            "note": "unrelated-card signed decision samples",
        },
        "publication_drain": {
            "status": "PASS" if saw_publication_pass else "SKIP",
            "note": "queue depth / row count / pointer watermark drain indicators",
        },
        "per_event_retry_history": {
            "status": "SKIP",
            "note": "not reconstructable from fixed-interval snapshots; requires the per-attempt event log",
        },
    }

    summary: Dict[str, Any] = {
        "kind": "e3_sampling",
        "mode": "fixed_interval_snapshot",
        "generated_at": _utc_now_iso(),
        "interval_s": interval,
        "duration_s": duration,
        "decision_node": _stored(decision_node),
        "samples_collected": collected,
        "scheduled_samples": scheduled,
        "completed": collected > 0 and not stopped_early,
        "stopped_early": stopped_early,
        "sink_errors": sink_errors,
        "overall": overall,
        "e3_evidence_claim": "NOT_CLAIMED",
        "status_note": (
            "fixed-interval snapshot sampling is not complete E3 evidence; the maximum supported "
            "claim is the weaker workload-level recovery-tail conclusion"
        ),
        "output_categories": categories,
        "limitations": _e3_limitations(config, probe),
    }
    if sink is None:
        summary["samples"] = retained
    return summary


# ---------------------------------------------------------------------------
# E4 fault matrix: pure fixture validation (no I/O, no mutation of inputs).
# ---------------------------------------------------------------------------

_E4_FAULT_MATRIX_ITEMS = (
    "redis_unavailable",
    "stale_hmac",
    "pointer_movement",
    "worker_restart",
    "lease_expiry",
    "unknown_ack",
)


def evaluate_fault_outcomes(outcomes: Iterable[Any]) -> Dict[str, Any]:
    """Validate recorded E4 fault-matrix fixtures (pure function).

    Each outcome is a mapping with ``fault_id``, ``observed`` (the final
    fail-safe decision observed under the fault) and ``reason`` (reason code).
    Optional ``expected`` re-asserts the fixture's expectation.

    Accepted: ``observed`` in {``DENY``, ``PENDING``} with a non-empty reason
    code (protocol E4: every fault must end in PENDING/DENY with the reason
    code preserved).

    Rejected: ``observed == "ALLOW"`` (fail-closed violation, FAIL),
    ``observed == "UNKNOWN"`` or missing (unproven), a missing/empty reason
    code, an ``expected`` of ``ALLOW`` or mismatching the observation, an
    unrecognized ``observed`` value, or a non-mapping entry. Empty input is
    BLOCKED. Inputs are never mutated; the verdict never certifies a live
    campaign run by itself.
    """
    rejections: List[Dict[str, Any]] = []
    accepted_fault_ids: List[str] = []
    total = 0
    for index, outcome in enumerate(outcomes):
        total += 1
        if not isinstance(outcome, Mapping):
            rejections.append({"index": index, "status": "BLOCKED", "reason": "outcome_not_a_mapping"})
            continue
        fault_id = outcome.get("fault_id")
        if not isinstance(fault_id, str) or not fault_id:
            rejections.append({"index": index, "status": "BLOCKED", "reason": "missing:fault_id"})
            continue
        observed_raw = outcome.get("observed")
        if observed_raw is None:
            rejections.append({"index": index, "fault_id": fault_id, "status": "BLOCKED", "reason": "missing:observed"})
            continue
        if not isinstance(observed_raw, str):
            rejections.append(
                {
                    "index": index,
                    "fault_id": fault_id,
                    "status": "BLOCKED",
                    "reason": "invalid:observed_type",
                }
            )
            continue
        observed = observed_raw.strip().upper()
        if observed == "ALLOW":
            rejections.append(
                {
                    "index": index,
                    "fault_id": fault_id,
                    "status": "FAIL",
                    "reason": "allow_observed_fail_closed_violation",
                }
            )
            continue
        if observed == "UNKNOWN":
            rejections.append({"index": index, "fault_id": fault_id, "status": "UNKNOWN", "reason": "unproven_outcome"})
            continue
        if observed not in {"DENY", "PENDING"}:
            rejections.append(
                {
                    "index": index,
                    "fault_id": fault_id,
                    "status": "BLOCKED",
                    "reason": "unrecognized_observed_value",
                    "observed": _stored(observed_raw),
                }
            )
            continue
        reason = outcome.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            rejections.append({"index": index, "fault_id": fault_id, "status": "BLOCKED", "reason": "missing:reason_code"})
            continue
        expected_raw = outcome.get("expected")
        if expected_raw is not None:
            if not isinstance(expected_raw, str):
                rejections.append(
                    {"index": index, "fault_id": fault_id, "status": "BLOCKED", "reason": "invalid:expected_type"}
                )
                continue
            expected = expected_raw.strip().upper()
            if expected == "ALLOW":
                rejections.append(
                    {"index": index, "fault_id": fault_id, "status": "FAIL", "reason": "expected_allow_rejected"}
                )
                continue
            if expected not in {"DENY", "PENDING"}:
                rejections.append(
                    {"index": index, "fault_id": fault_id, "status": "BLOCKED", "reason": "invalid:expected_value"}
                )
                continue
            if expected != observed:
                rejections.append(
                    {"index": index, "fault_id": fault_id, "status": "FAIL", "reason": "expected_mismatch"}
                )
                continue
        accepted_fault_ids.append(fault_id)
    if total == 0:
        verdict = "BLOCKED"
    elif any(item["status"] == "FAIL" for item in rejections):
        verdict = "FAIL"
    elif rejections:
        verdict = "BLOCKED"
    else:
        verdict = "PASS"
    return {
        "kind": "fault_outcome_validation",
        "fault_matrix_items": list(_E4_FAULT_MATRIX_ITEMS),
        "total": total,
        "accepted": len(accepted_fault_ids),
        "accepted_fault_ids": accepted_fault_ids,
        "rejected": len(rejections),
        "rejections": rejections,
        "verdict": verdict,
        "note": "pure fixture validation; a PASS verdict does not by itself prove a live campaign run",
    }


# ---------------------------------------------------------------------------
# CLI: --self-test only. No other command exists, and no flag performs I/O.
# ---------------------------------------------------------------------------


_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


def _run_self_test() -> int:
    import unittest

    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=_MODULE_DIR, pattern="test_e3_e4.py", top_level_dir=_MODULE_DIR
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="e3_e4.py",
        description=(
            "Read-only E3/E4 evidence helpers. This module has no network, database or "
            "service capability of its own; only --self-test is supported here."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the offline unit-test suite (test_e3_e4.py) with in-memory fakes; no services are touched",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
