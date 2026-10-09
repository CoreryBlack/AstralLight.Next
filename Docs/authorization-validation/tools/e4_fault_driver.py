#!/usr/bin/env python3
"""Offline-safe E4 fault-matrix protocol driver.

Execution class: **Exec-L1 offline** (plan, protocol, validation). Live fault
injection is **Exec-L3** and happens only through an injected controller inside
a future, user-approved campaign run. This module itself contains NO fault
primitive and performs NO I/O of any kind.

Scope and safety boundary
-------------------------

- Importing this module performs ZERO file, environment, network, subprocess,
  database, Redis, or service I/O. The only state created is plain constants.
- No CLI flag can execute a fault. The default/offline CLI (``--plan``) prints
  a plan in which every case is ``PLANNED`` and the live integration is
  ``BLOCKED``; it writes nothing and contacts nothing.
- Actual injection can only happen through an injected :class:`FaultController`
  supplied by a future campaign harness. The module never constructs one, and
  :func:`run_fault_matrix` / :func:`run_fault_case` carry an explicit
  ``allow_live_execution`` tripwire (default ``False``): with the default the
  driver returns ``BLOCKED`` without touching the controller even when a valid
  authorization is supplied.

Why the live integration is BLOCKED
-----------------------------------

There is no direct safe generic fault primitive in this repository. The
TrustGraph test-control plane
(``astral-trustgraph/src/api/test_control.rs``) deliberately
exposes a single read-only ``/internal/test-control/worker-id`` probe (no
mutation, no pump, no fault controls), and inventing shell/CLI fault commands
would create uncontrolled external side effects. A complete *live* fault
matrix therefore requires a platform-specific controller injected by the
campaign harness. This module defines that injected contract precisely (see
"Injected contract" below) and reports
``LIVE_FAULT_MATRIX_INTEGRATION == "BLOCKED"`` until such a controller exists
and an Exec-L3 run (allowlist, approval token, preflight, rollback, human
final review; AGENTS.md section 0C) is approved.

Injected contract: run authorization (supplied by the future caller)
--------------------------------------------------------------------

A mapping with run-scoped, structurally validated fields:

- ``run_id``: stable safe identifier (``experiment_common.SAFE_ID`` alphabet).
- ``exec_level``: must be exactly ``"Exec-L3"`` (live fault injection class).
- ``isolate_token``: run-scoped isolation token; safe identifier that must
  contain the ``run_id``; must differ from ``approval_token``.
- ``approval_token``: run-scoped approval token; safe identifier that must
  contain the ``run_id``. Token values are passed to the controller (which
  MUST verify them itself) but are NEVER copied into any result record.
- ``allowlist``: non-empty collection over the selected profile's registered
  fault ids; every executed fault must be listed.
- ``approved_by``: non-empty bounded approver/approval record string.

Driver-side validation is structural and therefore necessary but NOT
sufficient: the controller must independently verify the tokens (its
``preflight`` result must carry ``authorization_ok: True``).

Injected contract: FaultController hooks
----------------------------------------

All hooks receive a ``context`` mapping (``run_id``, ``fault_id``,
``operation_id``, ``attempt``, ``stage``, ``authorization``) and return a
mapping. ``capabilities`` takes no argument. Missing hooks, non-mapping
returns, and exceptions are mapped fail-closed (BLOCKED before any durable
action, UNKNOWN afterwards):

- ``capabilities()`` -> ``{"controller_id", "supported_faults", "isolation",
  "read_only_preflight": True}``. Static metadata; must declare the fault
  supported, the preflight read-only, and ``isolation`` as a safe identifier
  containing the current ``run_id``.
- ``preflight(ctx)`` -> ``{"ok": True, "authorization_ok": True, "checks"}``.
  Must be read-only; non-ok results BLOCK before any mutation.
- ``prepare(ctx)`` -> ``{"prepared": True, "prepare_ref": "<durable ref>"}``.
  Durable, idempotent intent record for the operation id. An explicit
  ``prepared: False`` BLOCKS; a claim without a durable ref is UNKNOWN.
- ``apply(ctx)`` -> ``{"applied": True, "apply_ref": "<ref>"}``. The
  Exec-L3 fault application itself. Timeouts/disconnects => UNKNOWN.
- ``observe(ctx)`` -> ``{"observed": "PENDING"|"DENY"|"ALLOW"|"UNKNOWN",
  "reason": "<reason code>", "host_admission": same domain,
  "evidence_generation": "<generation/epoch id>", "audit_ref": "<id>"}``.
  ``host_admission`` is required: a probe-level decision without the
  host-side admission outcome cannot prove fail-closed behavior.
- ``restore(ctx)`` -> ``{"restored": True, "restore_ref": "<ref>"}``. Safe
  restoration; runs exactly once whenever ``prepare`` was reached.
- ``reconcile(ctx)`` -> ``{"reconciled": True, "proof_ref": "<durable ref>",
  "durable_proof": True}``. Durable reconciliation of any unknown state;
  required before any retry is ever permitted.
- ``verify_postcondition(ctx)`` -> ``{"ok": True, "checks"}``. Proves the
  system is back to the pre-fault safe state; an explicit ``ok: False`` is a
  proven postcondition violation (FAIL).

Controllers may raise :class:`ControllerTimeout` /
:class:`ControllerDisconnect`; any other exception is mapped the same way
(UNKNOWN once a durable action was possible).

Execution protocol per fault (exactly one attempt; never retried)
-----------------------------------------------------------------

1. authorization validation (driver-side, structural) -> BLOCKED, no
   controller contact, on any problem;
2. ``capabilities`` + ``preflight`` -> BLOCKED before mutation on any problem;
3. ``prepare`` -> durable intent proof required before ``apply``;
4. ``apply`` -> the fault; UNKNOWN on timeout/disconnect (then ``observe`` is
   skipped and recovery runs immediately);
5. ``observe`` -> fail-closed decision classification (ALLOW anywhere =>
   FAIL; UNKNOWN/absent => UNKNOWN; PENDING/DENY require a reason code and a
   non-ALLOW host admission);
6. ``restore`` -> safe restoration (exactly once);
7. ``reconcile`` -> durable reconciliation; ``retry_permitted`` stays False
   until it proves durable state;
8. ``verify_postcondition`` -> restoration postcondition proof;
9. evidence requirements per case (see :data:`CASE_SPECS`);
10. cross-check of the observed outcome and reason through
    ``e3_e4.evaluate_fault_outcomes`` (PASS requires the validator to accept
    the fixture; an ALLOW observation becomes FAIL; a missing reason code
    becomes BLOCKED; an UNKNOWN observation stays UNKNOWN).

The overall per-fault status is the worst non-SKIP stage status (SKIP stages
either accompany a worse upstream status, which owns the outcome, or record a
not-applicable requirement; they stay visible in the record and never gate
the verdict by themselves). PASS additionally
requires proven restoration, proven reconciliation, a proven postcondition
and a PASS cross-check; a missing/UNKNOWN status or an unproven recovery can
never PASS. ``MAX_ATTEMPTS == 1``: the driver contains no retry loop, records
``retries: 0``, and marks ``retry_permitted`` False until ``reconcile``
proves durable state (any future attempt would need a NEW operation id and
its own approval).

Python 3.8+ standard library only. Offline unit tests live in
``test_e4_fault_driver.py`` next to this file and use fully fake controllers
only (no services, containers, or network are touched).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import (
    Any,
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
import experiment_common
import dependency_profiles as profiles
from experiment_common import EvidenceError, SAFE_ID, stable_id

__all__ = [
    "CASE_SPECS",
    "DEPENDENCY_PROFILES",
    "DEFAULT_PROFILE",
    "FAULT_CASES",
    "FAULT_CASES_BY_PROFILE",
    "FAULT_CASES_LEGACY_COMPAT",
    "ControllerDisconnect",
    "ControllerTimeout",
    "EXEC_LEVEL_LIVE",
    "EXEC_LEVEL_OFFLINE",
    "FaultController",
    "LIVE_FAULT_MATRIX_INTEGRATION",
    "LIVE_INTEGRATION_REASON",
    "MAX_ATTEMPTS",
    "build_fault_plan",
    "main",
    "run_fault_case",
    "run_fault_matrix",
    "validate_authorization",
]

# ---------------------------------------------------------------------------
# Constants and statuses.
# ---------------------------------------------------------------------------

DEFAULT_PROFILE = profiles.DEFAULT_PROFILE
DEPENDENCY_PROFILES: Tuple[str, ...] = profiles.PROFILE_IDS
FAULT_CASES_BY_PROFILE: Dict[str, Tuple[str, ...]] = profiles.E4_FAULTS_BY_PROFILE
FAULT_CASES_LEGACY_COMPAT: Tuple[str, ...] = profiles.LEGACY_REDIS_COMPAT_FAULTS
# Canonical default vocabulary is native single-node. The former Redis-bound
# vocabulary remains separately named so fake-controller coverage is explicit.
FAULT_CASES: Tuple[str, ...] = FAULT_CASES_BY_PROFILE[DEFAULT_PROFILE]
_ALL_REGISTERED_FAULTS = frozenset(
    fault_id for profile_faults in FAULT_CASES_BY_PROFILE.values() for fault_id in profile_faults
)

#: Hard attempt bound. The driver has no retry loop at all.
MAX_ATTEMPTS = 1

EXEC_LEVEL_LIVE = "Exec-L3"
EXEC_LEVEL_OFFLINE = "Exec-L1"

#: Honest integration claim: no live fault matrix has been run from this
#: module. See module docstring ("Why the live integration is BLOCKED").
LIVE_FAULT_MATRIX_INTEGRATION = "BLOCKED"
LIVE_INTEGRATION_REASON = (
    "No platform-specific fault controller exists in this repository: the "
    "TrustGraph test-control plane (astral-trustgraph/src/api/test_control.rs) "
    "exposes a read-only /internal/test-control/worker-id probe only, and no "
    "generic safe fault primitive exists. Live fault injection is Exec-L3 and "
    "requires a future user-approved campaign to inject a FaultController "
    "satisfying the documented contract; this module never applies faults."
)

_STATUS_RANK = {"FAIL": 0, "BLOCKED": 1, "UNKNOWN": 2, "PENDING": 3, "SKIP": 4, "PASS": 5}


def _worst_status(statuses: Any) -> str:
    """Worst-first aggregation; an empty set is BLOCKED (nothing proven)."""
    status_list = list(statuses)
    if not status_list:
        return "BLOCKED"
    return min(status_list, key=lambda status: _STATUS_RANK.get(status, _STATUS_RANK["UNKNOWN"]))


# ---------------------------------------------------------------------------
# Scrubbing: no hosts, no secrets, bounded strings in returned data (kept in
# sync with tools/e3_e4.py).
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


def _scrub_text(value: str) -> str:
    scrubbed = _URL_RE.sub(_SCRUB_REPLACEMENT, value)
    scrubbed = _IPV4_RE.sub(_SCRUB_REPLACEMENT, scrubbed)
    scrubbed = _HOSTNAME_RE.sub(_SCRUB_REPLACEMENT, scrubbed)
    return scrubbed


def _stored(value: Any, limit: int = _STORED_STRING_LIMIT) -> Any:
    if not isinstance(value, str):
        return value
    return _scrub_text(value[:limit])


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Frozen case specifications.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseSpec:
    """One E4 fault case: meaning, fail-closed expectation, evidence needs."""

    fault_id: str
    summary: str
    fail_closed_expectation: str
    #: Evidence keys required for a PASS: subsets of
    #: {"generation", "audit", "durable_reconcile_proof"}.
    requires_evidence: frozenset = frozenset()
    applicable_profiles: Tuple[str, ...] = ()
    dependency_classes: Tuple[str, ...] = ()
    compatibility_only: bool = False
    protocol_ref: str = "VALIDATION_PROTOCOL.md E4; AGENTS.md section 3"
    isolation_requirement: str = (
        "run-scoped isolated deployment; test data only; "
        "allowlisted fault inside an approved Exec-L3 window"
    )


CASE_SPECS: Dict[str, CaseSpec] = {
    "redis_unavailable": CaseSpec(
        fault_id="redis_unavailable",
        summary=(
            "Redis (cache-generation epoch astral:auth:cache_epoch / "
            "strict-evidence read path) unavailable during a decision"
        ),
        fail_closed_expectation=(
            "final decision is PENDING or DENY with a preserved reason code; "
            "no stale-cache hit and no source-read fallback may ALLOW"
        ),
        applicable_profiles=("redis-compat",),
        dependency_classes=("redis",),
        compatibility_only=True,
        protocol_ref="VALIDATION_PROTOCOL.md E4; AGENTS.md 3.2 fail-closed read gate",
        isolation_requirement=(
            "run-scoped isolated deployment; run-scoped Redis; test data only; "
            "allowlisted fault inside an approved Exec-L3 window"
        ),
    ),
    "stale_hmac": CaseSpec(
        fault_id="stale_hmac",
        summary=(
            "Gateway identity-header HMAC validation fails (stale replayed or "
            "forged signature); requests carrying gateway metadata that fails "
            "verification must be rejected, never accepted by fallback"
        ),
        fail_closed_expectation=(
            "request rejected (PENDING/DENY) with the signature-rejection "
            "reason code preserved; no fallback to raw identity headers"
        ),
        requires_evidence=frozenset({"audit"}),
        applicable_profiles=("redis-compat",),
        dependency_classes=("gateway_integrity",),
        compatibility_only=True,
        protocol_ref="VALIDATION_PROTOCOL.md E4; AGENTS.md 3.1/3.5 (audit chain)",
    ),
    "pointer_movement": CaseSpec(
        fault_id="pointer_movement",
        summary=(
            "cache-generation pointer/epoch moves (rotation) between candidate "
            "match and final read; stale evidence carries the old epoch"
        ),
        fail_closed_expectation=(
            "stale evidence must not be admitted; final decision PENDING/DENY "
            "with the observed generation/epoch recorded"
        ),
        requires_evidence=frozenset({"generation"}),
        applicable_profiles=("redis-compat",),
        dependency_classes=("cache", "redis"),
        compatibility_only=True,
        protocol_ref="VALIDATION_PROTOCOL.md E4; AGENTS.md 3.2 generation fence",
    ),
    "worker_restart": CaseSpec(
        fault_id="worker_restart",
        summary=(
            "projection/worker process restarts mid-flight (worker ownership "
            "lost); readiness and liveness are judged separately"
        ),
        fail_closed_expectation=(
            "decisions during the restart window are PENDING/DENY until a "
            "ready worker with restored ownership is proven"
        ),
        protocol_ref="VALIDATION_PROTOCOL.md E4; AGENTS.md 0D readiness/liveness",
    ),
    "lease_expiry": CaseSpec(
        fault_id="lease_expiry",
        summary=(
            "worker CAS lease expires (generation/token fence) while a delta "
            "is in flight; stale holders must not continue"
        ),
        fail_closed_expectation=(
            "in-flight work stops at the fence; decisions stay PENDING/DENY "
            "until a fresh lease/owning worker is proven"
        ),
        requires_evidence=frozenset({"generation"}),
        protocol_ref="VALIDATION_PROTOCOL.md E4; AGENTS.md 3.4 lease/fence",
    ),
    "unknown_ack": CaseSpec(
        fault_id="unknown_ack",
        summary=(
            "worker/transport ACK arrives without durable proof (stream "
            "disconnect or unknown outcome); the ACK must not be treated as "
            "durable proof"
        ),
        fail_closed_expectation=(
            "result recorded UNKNOWN, durable reconciliation must prove the "
            "terminal state before any retry; no automatic replay"
        ),
        requires_evidence=frozenset({"durable_reconcile_proof"}),
        protocol_ref="VALIDATION_PROTOCOL.md E4; AGENTS.md 0C/3.4 (durable proof)",
    ),
    "rabbit_transport_unavailable": CaseSpec(
        fault_id="rabbit_transport_unavailable",
        summary="RabbitMQ transport is unavailable during publication.",
        fail_closed_expectation=(
            "transport uncertainty yields PENDING/DENY until durable reconciliation; "
            "an ACK without proof cannot ALLOW"
        ),
        requires_evidence=frozenset({"durable_reconcile_proof"}),
        applicable_profiles=("standalone-rabbit", "distributed"),
        dependency_classes=("rabbitmq",),
        protocol_ref="VALIDATION_PROTOCOL.md E4; Rabbit transport profile",
        isolation_requirement=(
            "run-scoped isolated Rabbit deployment; test data only; "
            "live injection requires a future approved controller"
        ),
    ),
}

# Native single-node cases are declarations only. No native live controller is
# implemented here; plans are offline and native execution remains BLOCKED.
_CASE_METADATA = {
    "memory_channel_suspect": (
        "Memory projection channel becomes suspect; freshness evidence must defer.",
        "memory channel uncertainty yields PENDING/DENY; no prior generation may ALLOW",
        ("memory_projection_hub",),
        frozenset({"generation"}),
    ),
    "memory_invalidation_omission": (
        "Memory projection invalidation notification is omitted.",
        "missing invalidation yields PENDING/DENY until durable freshness is proven",
        ("memory_projection_hub",),
        frozenset({"generation"}),
    ),
    "local_bus_owner_loss": (
        "LocalBus or LocalProjectionBus owner is lost.",
        "owner loss yields PENDING/DENY; stale local state cannot ALLOW",
        ("local_bus", "local_projection_bus"),
        frozenset(),
    ),
    "local_bus_overflow": (
        "LocalBus/LocalProjectionBus bounded channel overflows.",
        "overflow yields PENDING/DENY; dropped completion cannot ALLOW",
        ("local_bus", "local_projection_bus"),
        frozenset(),
    ),
    "local_bus_unknown_completion": (
        "LocalBus/LocalProjectionBus completion is unknown.",
        "unknown completion stays UNKNOWN or fails closed; no automatic replay",
        ("local_bus", "local_projection_bus"),
        frozenset({"durable_reconcile_proof"}),
    ),
    "source_commit_unknown": (
        "Authoritative MySQL source commit outcome is unknown.",
        "unknown commit yields PENDING/DENY until durable reconciliation proves state",
        ("authoritative_database",),
        frozenset({"durable_reconcile_proof"}),
    ),
    "worker_death_sticky": (
        "Publication worker dies and remains stopped; no automatic restart is assumed.",
        "worker death yields PENDING/DENY until readiness and ownership are proven",
        ("publication_worker",),
        frozenset(),
    ),
    "writer_lease_loss": (
        "Single-node writer lease is lost.",
        "lease loss stops stale writers and yields PENDING/DENY",
        ("single_writer_lease",),
        frozenset({"generation"}),
    ),
    "current_pointer_movement": (
        "Current authorization pointer moves during a decision.",
        "stale pointer evidence yields PENDING/DENY with generation recorded",
        ("cache", "authoritative_database"),
        frozenset({"generation"}),
    ),
    "hmac_failure": (
        "Gateway identity-header HMAC validation fails.",
        "invalid gateway integrity yields DENY/PENDING; no raw-header fallback",
        ("gateway_integrity",),
        frozenset({"audit"}),
    ),
    "mysql_unavailable": (
        "Authoritative MySQL is unavailable during a decision.",
        "database uncertainty yields PENDING/DENY; no source fallback may ALLOW",
        ("authoritative_database",),
        frozenset(),
    ),
}
for _fault_id, (_summary, _expectation, _dependencies, _evidence) in _CASE_METADATA.items():
    CASE_SPECS[_fault_id] = CaseSpec(
        fault_id=_fault_id,
        summary=_summary,
        fail_closed_expectation=_expectation,
        requires_evidence=_evidence,
        applicable_profiles=("native-single-node",),
        dependency_classes=_dependencies,
        protocol_ref="VALIDATION_PROTOCOL.md E4; native single-node profile",
        isolation_requirement=(
            "run-scoped isolated native single-node deployment; test data only; "
            "live injection requires a future approved controller"
        ),
    )
for _fault_id in FAULT_CASES_LEGACY_COMPAT:
    _spec = CASE_SPECS[_fault_id]
    CASE_SPECS[_fault_id] = replace(
        _spec,
        applicable_profiles=("redis-compat",),
        dependency_classes=profiles.FAULT_DEPENDENCIES_BY_PROFILE["redis-compat"][_fault_id],
        compatibility_only=True,
    )
for _fault_id, _spec in list(CASE_SPECS.items()):
    _applicable_profiles = tuple(
        profile
        for profile in DEPENDENCY_PROFILES
        if _fault_id in FAULT_CASES_BY_PROFILE[profile]
    )
    if _applicable_profiles:
        _dependencies = tuple(
            sorted(
                {
                    dependency
                    for profile in _applicable_profiles
                    for dependency in profiles.FAULT_DEPENDENCIES_BY_PROFILE[profile][_fault_id]
                }
            )
        )
        CASE_SPECS[_fault_id] = replace(
            _spec,
            applicable_profiles=_applicable_profiles,
            dependency_classes=_dependencies,
            compatibility_only=_fault_id in FAULT_CASES_LEGACY_COMPAT,
        )


class ControllerTimeout(RuntimeError):
    """Controller hook exceeded its budget; durable state is unproven."""


class ControllerDisconnect(RuntimeError):
    """Controller stream/connection broke mid-hook; durable state is unproven."""


@runtime_checkable
class FaultController(Protocol):
    """Injected contract (see module docstring). Implementations are supplied
    by a future Exec-L3 campaign harness; this module never constructs one."""

    def capabilities(self) -> Mapping[str, Any]: ...

    def preflight(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def prepare(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def apply(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def observe(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def restore(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def reconcile(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def verify_postcondition(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...


# ---------------------------------------------------------------------------
# Run authorization (structural validation; controller verifies token values).
# ---------------------------------------------------------------------------


def validate_authorization(
    authorization: Any,
    fault_id: Optional[str] = None,
    *,
    profile: str = DEFAULT_PROFILE,
) -> List[str]:
    """Structurally validate the run-scoped authorization mapping.

    Returns a list of problems (empty = valid). Never mutates the input and
    never returns or logs token values. Structural validity is necessary but
    NOT sufficient: the controller must verify the tokens itself and report
    ``authorization_ok`` in its preflight result.
    """
    try:
        canonical_profile = profiles.normalize_profile(profile)
    except ValueError as error:
        return [str(error)]
    allowed_faults = FAULT_CASES_BY_PROFILE[canonical_profile]
    if not isinstance(authorization, Mapping):
        return ["authorization_not_a_mapping"]
    problems: List[str] = []
    run_id = authorization.get("run_id")
    if not isinstance(run_id, str) or not SAFE_ID.fullmatch(run_id):
        problems.append("invalid:run_id")
    if authorization.get("exec_level") != EXEC_LEVEL_LIVE:
        problems.append("invalid:exec_level")
    approved_by = authorization.get("approved_by")
    if not isinstance(approved_by, str) or not approved_by.strip() or len(approved_by) > 120:
        problems.append("invalid:approved_by")
    for key in ("isolate_token", "approval_token"):
        token = authorization.get(key)
        if not isinstance(token, str) or not SAFE_ID.fullmatch(token):
            problems.append("invalid:" + key)
        elif isinstance(run_id, str) and run_id and run_id not in token:
            problems.append("not_run_scoped:" + key)
    isolate = authorization.get("isolate_token")
    approval = authorization.get("approval_token")
    if (
        isinstance(isolate, str)
        and isinstance(approval, str)
        and isolate
        and isolate == approval
    ):
        problems.append("tokens_not_distinct")
    allowlist = authorization.get("allowlist")
    if not isinstance(allowlist, (list, tuple, frozenset, set)) or not list(allowlist):
        problems.append("invalid:allowlist")
    else:
        for entry in allowlist:
            if not isinstance(entry, str) or entry not in allowed_faults:
                problems.append("invalid:allowlist_entry")
    if fault_id is not None:
        if not isinstance(fault_id, str) or fault_id not in allowed_faults:
            problems.append("invalid:fault_id")
        elif not isinstance(allowlist, (list, tuple, frozenset, set)) or fault_id not in allowlist:
            problems.append("fault_not_in_allowlist")
    return problems


def _authorization_summary(authorization: Any) -> Optional[Dict[str, Any]]:
    """Token-free summary of the authorization for result records."""
    if not isinstance(authorization, Mapping):
        return None
    allowlist = authorization.get("allowlist")
    return {
        "run_id": authorization.get("run_id") if isinstance(authorization.get("run_id"), str) else None,
        "exec_level": authorization.get("exec_level"),
        "allowlist": sorted(str(entry) for entry in allowlist)
        if isinstance(allowlist, (list, tuple, frozenset, set))
        else None,
        "approved_by": authorization.get("approved_by"),
        "token_values_recorded": False,
    }


# ---------------------------------------------------------------------------
# Hook invocation and per-stage validation (fail-closed mapping).
# ---------------------------------------------------------------------------


def _call_hook(
    controller: Any, hook_name: str, context: Optional[Mapping[str, Any]], *, mutable: bool
) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """Invoke one controller hook.

    Returns ``(status, detail, payload)``. ``PASS`` means the hook returned a
    mapping (payload set). ``BLOCKED`` means the stage could not be executed
    (missing hook, non-mapping return, or exception before any durable action
    was possible). ``UNKNOWN`` means a timeout/disconnect/exception left the
    durable state unproven (only possible once a durable action was possible).
    """
    hook = getattr(controller, hook_name, None)
    if hook is None or not callable(hook):
        return "BLOCKED", "controller_hook_missing:" + hook_name, {}
    try:
        # capabilities is static and takes no context argument.
        raw = hook() if context is None else hook(context)
    except ControllerTimeout:
        return "UNKNOWN", "controller_timeout", {}
    except ControllerDisconnect:
        return "UNKNOWN", "controller_disconnect", {}
    except Exception as error:  # noqa: BLE001 - any controller failure is fail-closed
        if mutable:
            return "UNKNOWN", "controller_error:" + type(error).__name__, {}
        return "BLOCKED", "controller_error:" + type(error).__name__, {}
    if not isinstance(raw, Mapping):
        detail = "controller_returned_non_mapping"
        return ("UNKNOWN" if mutable else "BLOCKED"), detail, {}
    return "PASS", None, dict(raw)


def _stage_record(
    status: str, detail: Optional[str], payload: Optional[Mapping[str, Any]] = None,
    ref_key: Optional[str] = None,
) -> Dict[str, Any]:
    record: Dict[str, Any] = {"status": status, "detail": detail}
    if ref_key and isinstance(payload, Mapping):
        ref = payload.get(ref_key)
        if isinstance(ref, str) and ref.strip():
            record[ref_key] = _stored(ref)
    return record


def _validate_prepare(status: str, detail: Optional[str], payload: Mapping[str, Any]) -> Tuple[str, Optional[str]]:
    if status != "PASS":
        return status, detail
    if payload.get("prepared") is False:
        return "BLOCKED", "prepare_refused_by_controller"
    if not payload.get("prepared"):
        return "UNKNOWN", "prepare_unproven"
    ref = payload.get("prepare_ref")
    if not isinstance(ref, str) or not ref.strip():
        return "UNKNOWN", "prepare_durable_ref_missing"
    return "PASS", None


def _validate_apply(status: str, detail: Optional[str], payload: Mapping[str, Any]) -> Tuple[str, Optional[str]]:
    if status != "PASS":
        return status, detail
    if payload.get("applied") is False:
        return "BLOCKED", "apply_refused_by_controller"
    if not payload.get("applied"):
        return "UNKNOWN", "apply_unproven"
    ref = payload.get("apply_ref")
    if not isinstance(ref, str) or not ref.strip():
        return "UNKNOWN", "apply_ref_missing"
    return "PASS", None


_DECISION_DOMAIN = {"PENDING", "DENY", "ALLOW", "UNKNOWN"}


def _classify_observation(
    status: str, detail: Optional[str], payload: Mapping[str, Any]
) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """Classify the observation payload fail-closed.

    Returns ``(stage_status, stage_detail, extracted)``. ``extracted`` carries
    normalized ``observed`` / ``reason`` / ``host_admission`` (upper-cased or
    None) for the evidence stage and the cross-check.
    """
    if status != "PASS":
        return status, detail, {"observed": None, "reason": None, "host_admission": None}
    extracted: Dict[str, Any] = {
        "observed": None,
        "reason": None,
        "host_admission": None,
        "evidence_generation": None,
        "audit_ref": None,
    }
    for evidence_key in ("evidence_generation", "audit_ref"):
        evidence_value = payload.get(evidence_key)
        extracted[evidence_key] = (
            evidence_value.strip() if isinstance(evidence_value, str) else None
        )
    observed_raw = payload.get("observed")
    if observed_raw is None:
        return "BLOCKED", "missing:observed", extracted
    if not isinstance(observed_raw, str):
        return "BLOCKED", "invalid:observed_type", extracted
    observed = observed_raw.strip().upper()
    extracted["observed"] = observed
    if observed == "ALLOW":
        return "FAIL", "allow_observed_fail_closed_violation", extracted
    if observed == "UNKNOWN":
        return "UNKNOWN", "unproven_outcome", extracted
    if observed not in {"DENY", "PENDING"}:
        return "BLOCKED", "unrecognized_observed_value", extracted
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return "BLOCKED", "missing:reason_code", extracted
    extracted["reason"] = reason.strip()
    host_raw = payload.get("host_admission")
    if host_raw is None:
        return "UNKNOWN", "host_admission_not_observed", extracted
    if not isinstance(host_raw, str):
        return "BLOCKED", "invalid:host_admission_type", extracted
    host = host_raw.strip().upper()
    extracted["host_admission"] = host
    if host == "ALLOW":
        return "FAIL", "host_admission_allow_violation", extracted
    if host == "UNKNOWN":
        return "UNKNOWN", "host_admission_unknown", extracted
    if host not in {"DENY", "PENDING"}:
        return "BLOCKED", "unrecognized_host_admission", extracted
    return "PASS", None, extracted


def _validate_restore(status: str, detail: Optional[str], payload: Mapping[str, Any]) -> Tuple[str, Optional[str]]:
    if status != "PASS":
        return status, detail
    if not payload.get("restored"):
        return "UNKNOWN", "restoration_unproven"
    return "PASS", None


def _validate_reconcile(status: str, detail: Optional[str], payload: Mapping[str, Any]) -> Tuple[str, Optional[str]]:
    if status != "PASS":
        return status, detail
    if not payload.get("reconciled"):
        return "UNKNOWN", "reconciliation_unproven"
    ref = payload.get("proof_ref")
    if not isinstance(ref, str) or not ref.strip():
        return "UNKNOWN", "reconciliation_proof_ref_missing"
    if payload.get("durable_proof") is not True:
        return "UNKNOWN", "durable_reconciliation_proof_missing"
    return "PASS", None


def _validate_postcondition(status: str, detail: Optional[str], payload: Mapping[str, Any]) -> Tuple[str, Optional[str]]:
    if status != "PASS":
        return status, detail
    if payload.get("ok") is False:
        return "FAIL", "postcondition_violation"
    if not payload.get("ok"):
        return "UNKNOWN", "postcondition_unproven"
    return "PASS", None


def _stage_evidence(
    spec: CaseSpec,
    observation: Mapping[str, Any],
    reconcile_payload: Mapping[str, Any],
    reconcile_status: str,
) -> Dict[str, Any]:
    """Check the case's source audit / generation / durable-proof evidence.

    Observation-derived evidence (generation/audit) is SKIP (not BLOCKED) when
    no observation exists at all: the upstream stage already owns that
    failure. Reconcile-derived evidence (durable_reconcile_proof) is always
    evaluated against the reconcile result.
    """
    required = sorted(spec.requires_evidence)
    record: Dict[str, Any] = {"status": "SKIP", "detail": None, "required": required, "found": {}}
    if not required:
        record["detail"] = "no_case_specific_evidence_required"
        return record
    no_observation = observation.get("observed") is None
    if no_observation and set(required).issubset({"generation", "audit"}):
        record["detail"] = "no_observation_for_evidence"
        return record
    problems: List[str] = []
    for item in required:
        if item == "generation":
            value = observation.get("evidence_generation")
            if isinstance(value, str) and value.strip():
                record["found"]["evidence_generation"] = _stored(value)
            else:
                problems.append("missing_evidence:evidence_generation")
        elif item == "audit":
            value = observation.get("audit_ref")
            if isinstance(value, str) and value.strip():
                record["found"]["audit_ref"] = _stored(value)
            else:
                problems.append("missing_evidence:audit_ref")
        elif item == "durable_reconcile_proof":
            ref = reconcile_payload.get("proof_ref") if isinstance(reconcile_payload, Mapping) else None
            if (
                reconcile_status == "PASS"
                and isinstance(reconcile_payload, Mapping)
                and bool(reconcile_payload.get("durable_proof"))
                and isinstance(ref, str)
                and ref.strip()
            ):
                record["found"]["durable_reconcile_proof"] = _stored(ref)
            else:
                problems.append("missing_evidence:durable_reconcile_proof")
        else:
            # Frozen specs only; reaching this is a programming error.
            problems.append("unknown_evidence_requirement:" + item)
    if problems:
        record["status"] = "BLOCKED"
        record["detail"] = ";".join(problems)
    else:
        record["status"] = "PASS"
    return record


# ---------------------------------------------------------------------------
# Per-fault execution (one attempt).
# ---------------------------------------------------------------------------


def run_fault_case(
    controller: Any,
    authorization: Any,
    fault_id: Any,
    *,
    allow_live_execution: bool = False,
    clock: Optional[Any] = None,
    profile: str = DEFAULT_PROFILE,
) -> Dict[str, Any]:
    """Run the E4 protocol for exactly one fault case, once (never retried).

    With ``allow_live_execution=False`` (the default) the driver returns
    BLOCKED without touching the controller. Returns a token-free result
    record; the overall status is the worst stage status (AGENTS.md 7.1
    semantics: SKIP is never PASS, UNKNOWN requires reconciliation).
    """
    clock_fn = clock if callable(clock) else time.time
    started = clock_fn()
    result: Dict[str, Any] = {
        "kind": "e4_fault_case_result",
        "schemaVersion": 1,
        "fault_id": fault_id if isinstance(fault_id, str) else None,
        "attempt": 1,
        "retries": 0,
        "max_attempts": MAX_ATTEMPTS,
        "stages": {},
    }
    stages = result["stages"]

    def finish(extra_note: Optional[str] = None) -> Dict[str, Any]:
        # SKIP stages are excluded from the verdict: a SKIP either accompanies
        # a worse upstream status (the failing stage owns the outcome) or
        # records a not-applicable requirement, and never gates PASS by
        # itself. They stay visible in "stages" and "skipped_stages".
        statuses = [
            record["status"]
            for record in stages.values()
            if isinstance(record, Mapping)
            and "status" in record
            and record["status"] != "SKIP"
        ]
        result["overall"] = _worst_status(statuses)
        result["skipped_stages"] = sorted(
            name
            for name, record in stages.items()
            if isinstance(record, Mapping) and record.get("status") == "SKIP"
        )
        result["started_at"] = _utc_now_iso()
        result["ended_at"] = _utc_now_iso()
        result["duration_s"] = round(max(0.0, clock_fn() - started), 6)
        if extra_note:
            result["note"] = extra_note
        return result

    try:
        canonical_profile = profiles.normalize_profile(profile)
    except ValueError as error:
        stages["profile"] = {"status": "BLOCKED", "detail": str(error)}
        return finish("unknown profile rejected before controller contact")
    result["profile"] = canonical_profile
    applicable_faults = FAULT_CASES_BY_PROFILE[canonical_profile]

    if allow_live_execution is not True:
        stages["live_gate"] = {"status": "BLOCKED", "detail": "allow_live_execution_false"}
        return finish(
            "live-execution tripwire closed; allow_live_execution=True is only "
            "valid inside an approved Exec-L3 campaign run"
        )

    spec = CASE_SPECS.get(fault_id) if isinstance(fault_id, str) else None
    if spec is None:
        stages["validation"] = {"status": "BLOCKED", "detail": "unknown_fault_id"}
        return finish(
            "fault id is not part of the registered E4 matrices; unvalidated fault "
            "entries are refused"
        )
    if fault_id not in applicable_faults:
        stages["validation"] = {
            "status": "BLOCKED",
            "detail": "fault_not_applicable_to_profile",
        }
        return finish("fault is not registered for the selected profile")
    result["fault_id"] = spec.fault_id
    result["fail_closed_expectation"] = spec.fail_closed_expectation

    if controller is None:
        stages["controller"] = {"status": "BLOCKED", "detail": "no_controller_injected"}
        return finish("no FaultController injected; live integration is BLOCKED")

    problems = validate_authorization(authorization, spec.fault_id, profile=canonical_profile)
    stages["authorization"] = {
        "status": "PASS" if not problems else "BLOCKED",
        "detail": None if not problems else ";".join(problems[:8]),
        "summary": _authorization_summary(authorization),
    }
    if problems:
        return finish("authorization rejected before any controller contact")
    if canonical_profile != "redis-compat":
        stages["profile_execution"] = {
            "status": "BLOCKED",
            "detail": "native_fault_controller_not_implemented",
        }
        return finish(
            "native/Rabbit fault execution is BLOCKED until a profile-specific "
            "controller is approved; the legacy controller is compat-only"
        )
    run_id = authorization["run_id"]
    result["run_id"] = run_id
    result["campaign_id"] = authorization.get("campaign_id") if isinstance(authorization.get("campaign_id"), str) else None

    try:
        operation_id = stable_id(run_id, "e4-fault:" + spec.fault_id + ":attempt-1")
    except EvidenceError:
        stages["authorization"] = {
            "status": "BLOCKED",
            "detail": "operation_id_derivation_failed",
            "summary": _authorization_summary(authorization),
        }
        return finish("operation id could not be derived from the run id")
    result["operation_id"] = operation_id

    context_base: Dict[str, Any] = {
        "run_id": run_id,
        "fault_id": spec.fault_id,
        "operation_id": operation_id,
        "attempt": 1,
        "authorization": dict(authorization),  # controller MUST verify tokens itself
    }

    def ctx(stage: str) -> Dict[str, Any]:
        merged = dict(context_base)
        merged["stage"] = stage
        return merged

    # --- capabilities (static, no context) ---------------------------------
    status, detail, payload = _call_hook(controller, "capabilities", None, mutable=False)
    if status == "PASS":
        supported = payload.get("supported_faults")
        if not isinstance(supported, (list, tuple, frozenset, set)) or spec.fault_id not in supported:
            status, detail = "BLOCKED", "fault_not_supported_by_controller"
        elif payload.get("read_only_preflight") is not True:
            status, detail = "BLOCKED", "controller_does_not_declare_read_only_preflight"
        else:
            isolation = payload.get("isolation")
            if (
                not isinstance(isolation, str)
                or not SAFE_ID.fullmatch(isolation)
                or run_id not in isolation
            ):
                status, detail = "BLOCKED", "controller_isolation_not_run_scoped"
            else:
                # Store only scrubbed, allowlisted metadata; never copy the
                # whole controller payload into the result.
                controller_id = payload.get("controller_id")
                payload = {
                    "controller_id": _stored(controller_id)
                    if isinstance(controller_id, str) and controller_id.strip()
                    else None,
                    "isolation_declared": True,
                }
    stages["capabilities"] = _stage_record(status, detail, payload)
    if status != "PASS":
        return finish("controller capabilities rejected before any mutation")

    # --- preflight (declared read-only) ------------------------------------
    status, detail, payload = _call_hook(controller, "preflight", ctx("preflight"), mutable=False)
    if status == "PASS":
        if payload.get("ok") is not True:
            status, detail = "BLOCKED", "preflight_failed"
        elif payload.get("authorization_ok") is not True:
            status, detail = "BLOCKED", "controller_rejected_authorization"
    stages["preflight"] = _stage_record(status, detail, payload)
    if status != "PASS":
        return finish("preflight failed before any mutation")

    # --- prepare (durable intent) -------------------------------------------
    p_status, p_detail, p_payload = _call_hook(controller, "prepare", ctx("prepare"), mutable=True)
    p_status, p_detail = _validate_prepare(p_status, p_detail, p_payload)
    stages["prepare"] = _stage_record(p_status, p_detail, p_payload, ref_key="prepare_ref")
    if p_status == "BLOCKED":
        # Explicit refusal: the controller claims no durable intent exists.
        return finish("prepare refused before any durable intent was proven")

    # --- apply + observe (only after a proven durable prepare) --------------
    observation: Dict[str, Any] = {"observed": None, "reason": None, "host_admission": None}
    if p_status == "PASS":
        a_status, a_detail, a_payload = _call_hook(controller, "apply", ctx("apply"), mutable=True)
        a_status, a_detail = _validate_apply(a_status, a_detail, a_payload)
        stages["apply"] = _stage_record(a_status, a_detail, a_payload, ref_key="apply_ref")
        if a_status == "PASS":
            o_status, o_detail, o_payload = _call_hook(controller, "observe", ctx("observe"), mutable=True)
            o_status, o_detail, observation = _classify_observation(o_status, o_detail, o_payload)
        else:
            o_status, o_detail = "SKIP", "apply_not_proven"
    else:
        # prepare UNKNOWN: durable intent may exist; never apply on top of it.
        stages["apply"] = {"status": "SKIP", "detail": "prepare_unproven_apply_skipped"}
        o_status, o_detail = "SKIP", "prepare_unproven"
    stages["observe"] = {
        "status": o_status,
        "detail": o_detail,
        "observed": observation.get("observed"),
        "reason": _stored(observation.get("reason")) if isinstance(observation.get("reason"), str) else None,
        "host_admission": observation.get("host_admission"),
    }

    # --- recovery path: restore, reconcile, postcondition (exactly once) ----
    r_status, r_detail, r_payload = _call_hook(controller, "restore", ctx("restore"), mutable=True)
    r_status, r_detail = _validate_restore(r_status, r_detail, r_payload)
    stages["restore"] = _stage_record(r_status, r_detail, r_payload, ref_key="restore_ref")

    c_status, c_detail, c_payload = _call_hook(controller, "reconcile", ctx("reconcile"), mutable=True)
    c_status, c_detail = _validate_reconcile(c_status, c_detail, c_payload)
    stages["reconcile"] = _stage_record(c_status, c_detail, c_payload, ref_key="proof_ref")

    pc_status, pc_detail, pc_payload = _call_hook(
        controller, "verify_postcondition", ctx("verify_postcondition"), mutable=True
    )
    pc_status, pc_detail = _validate_postcondition(pc_status, pc_detail, pc_payload)
    stages["postcondition"] = _stage_record(pc_status, pc_detail, pc_payload)

    # --- evidence requirements ----------------------------------------------
    stages["evidence"] = _stage_evidence(spec, observation, c_payload, c_status)

    # --- cross-check through the pure e3_e4 validator ------------------------
    if observation.get("observed") is None:
        stages["cross_check"] = {"status": "SKIP", "detail": "no_observation_to_cross_check"}
    else:
        fixture = {
            "fault_id": spec.fault_id,
            "observed": observation.get("observed"),
            "reason": observation.get("reason"),
        }
        cross = e3_e4.evaluate_fault_outcomes([fixture])
        # Map the validator's per-rejection statuses faithfully (its aggregate
        # verdict collapses UNKNOWN rejections into BLOCKED, which would
        # misreport an unproven outcome as a missing precondition).
        rejection_statuses = [item["status"] for item in cross["rejections"]]
        stages["cross_check"] = {
            "status": "PASS" if not rejection_statuses else _worst_status(rejection_statuses),
            "detail": None if not rejection_statuses else "validator_rejected_fixture",
            "rejections": cross["rejections"],
            "validator_verdict": cross["verdict"],
            "validator_kind": cross["kind"],
        }

    # --- result fields -------------------------------------------------------
    result["observed"] = observation.get("observed")
    result["reason"] = _stored(observation.get("reason")) if isinstance(observation.get("reason"), str) else None
    result["host_admission"] = observation.get("host_admission")
    result["restoration_proven"] = stages["restore"]["status"] == "PASS"
    result["reconciliation_proven"] = stages["reconcile"]["status"] == "PASS"
    result["postcondition_proven"] = stages["postcondition"]["status"] == "PASS"
    result["retry_permitted"] = result["reconciliation_proven"]
    if not result["retry_permitted"]:
        result["retry_requires"] = (
            "durable reconciliation (reconcile with a proof_ref) must prove the "
            "durable state first; any new attempt requires a NEW operation id "
            "and its own approval; this driver never retries (MAX_ATTEMPTS=1)"
        )
    return finish()


# ---------------------------------------------------------------------------
# Matrix execution.
# ---------------------------------------------------------------------------


def run_fault_matrix(
    controller: Any,
    authorization: Any,
    *,
    fault_ids: Optional[Sequence[str]] = None,
    allow_live_execution: bool = False,
    clock: Optional[Any] = None,
    profile: str = DEFAULT_PROFILE,
) -> Dict[str, Any]:
    """Run the E4 fault matrix (or a subset), one attempt per fault.

    Matrix-level gates run before any controller contact: the
    ``allow_live_execution`` tripwire, controller presence, and structural
    authorization validation. Each fault is then run once through
    :func:`run_fault_case`. The result never contains authorization token
    values and never claims a live campaign run by itself.
    """
    try:
        canonical_profile = profiles.normalize_profile(profile)
    except ValueError as error:
        return {
            "kind": "e4_fault_matrix_run",
            "schemaVersion": 1,
            "profile": profile,
            "overall": "BLOCKED",
            "note": "unknown profile rejected before controller contact",
            "profile_error": str(error),
            "faults": [],
            "integration_claim": LIVE_FAULT_MATRIX_INTEGRATION,
        }
    profile_faults = FAULT_CASES_BY_PROFILE[canonical_profile]
    requested = list(profile_faults) if fault_ids is None else list(fault_ids)
    matrix: Dict[str, Any] = {
        "kind": "e4_fault_matrix_run",
        "schemaVersion": 1,
        "profile": canonical_profile,
        "max_attempts": MAX_ATTEMPTS,
        "fault_matrix_items": list(profile_faults),
        "requested_faults": requested,
        "faults": [],
        "limitations": [],
    }
    execution_class = "Exec-L3-live-injected" if allow_live_execution else "Exec-L1-offline-gate-closed"
    matrix["execution_class"] = execution_class
    matrix["live_gate"] = {
        "allow_live_execution": bool(allow_live_execution),
        "authorization_valid": not validate_authorization(authorization, profile=canonical_profile),
        "controller_injected": controller is not None,
    }

    if not allow_live_execution:
        matrix["overall"] = "BLOCKED"
        matrix["note"] = (
            "live-execution tripwire closed; this offline gate exists so the "
            "CLI or an accidental call can never apply a fault"
        )
        matrix["integration_claim"] = LIVE_FAULT_MATRIX_INTEGRATION
        return matrix
    if canonical_profile != "redis-compat":
        matrix["overall"] = "BLOCKED"
        matrix["note"] = (
            "native/Rabbit fault execution has no safe controller implementation; "
            "offline plans are declarative and live execution remains BLOCKED"
        )
        matrix["integration_claim"] = LIVE_FAULT_MATRIX_INTEGRATION
        return matrix
    if controller is None:
        matrix["overall"] = "BLOCKED"
        matrix["note"] = "no FaultController injected; live fault matrix integration is BLOCKED"
        matrix["integration_claim"] = LIVE_FAULT_MATRIX_INTEGRATION
        return matrix
    problems = validate_authorization(authorization, profile=canonical_profile)
    if problems:
        matrix["overall"] = "BLOCKED"
        matrix["note"] = "authorization rejected before any controller contact"
        matrix["authorization_problems"] = problems
        matrix["authorization"] = _authorization_summary(authorization)
        matrix["integration_claim"] = LIVE_FAULT_MATRIX_INTEGRATION
        return matrix

    matrix["run_id"] = authorization["run_id"]
    matrix["campaign_id"] = (
        authorization.get("campaign_id") if isinstance(authorization.get("campaign_id"), str) else None
    )
    matrix["authorization"] = _authorization_summary(authorization)

    faults = [
        run_fault_case(
            controller,
            authorization,
            fault_id,
            allow_live_execution=True,
            clock=clock,
            profile=canonical_profile,
        )
        for fault_id in requested
    ]
    matrix["faults"] = faults
    matrix["overall"] = _worst_status([fault["overall"] for fault in faults]) if faults else "BLOCKED"
    passed = {fault["fault_id"] for fault in faults if fault.get("overall") == "PASS"}
    matrix["matrix_complete"] = set(profile_faults).issubset(passed)
    matrix["missing_faults"] = [item for item in profile_faults if item not in set(requested)]
    matrix["integration_claim"] = LIVE_FAULT_MATRIX_INTEGRATION
    matrix["note"] = (
        "one attempt per fault (MAX_ATTEMPTS=1); UNKNOWN results require "
        "durable reconciliation before any new approved attempt"
    )
    matrix["limitations"] = [
        {
            "item": "host_admission_source",
            "status": "SKIP",
            "note": (
                "host_admission is reported by the injected controller's "
                "observe hook; an independent host-side cross-check belongs to "
                "the campaign request-side event logs"
            ),
        },
        {
            "item": "no_automatic_replay",
            "status": "PASS",
            "note": (
                "the driver contains no retry loop; retries are forbidden "
                "without proven durable reconciliation and a new operation id"
            ),
        },
        {
            "item": "live_integration",
            "status": LIVE_FAULT_MATRIX_INTEGRATION,
            "note": LIVE_INTEGRATION_REASON,
        },
    ]
    return matrix


# ---------------------------------------------------------------------------
# Offline plan (no I/O, no controller, no fault).
# ---------------------------------------------------------------------------


def build_fault_plan(
    run_id: Optional[str] = None,
    campaign_id: Optional[str] = None,
    *,
    profile: str = DEFAULT_PROFILE,
) -> Dict[str, Any]:
    """Build the offline E4 fault plan. Pure function; performs no I/O."""
    try:
        canonical_profile = profiles.normalize_profile(profile)
    except ValueError as error:
        return {
            "kind": "e4_fault_plan",
            "schemaVersion": 1,
            "profile": profile,
            "status": "BLOCKED",
            "profile_error": str(error),
            "cases": [],
            "offline_guarantee": "unknown profile rejected without I/O",
        }
    profile_faults = FAULT_CASES_BY_PROFILE[canonical_profile]
    return {
        "kind": "e4_fault_plan",
        "schemaVersion": 1,
        "profile": canonical_profile,
        "run_id": run_id,
        "campaign_id": campaign_id,
        "execution_class_planned": EXEC_LEVEL_OFFLINE + "-offline-plan (live injection is Exec-L3)",
        "max_attempts": MAX_ATTEMPTS,
        "fault_matrix_items": list(profile_faults),
        "cases": [
            {
                "fault_id": fault_id,
                "summary": CASE_SPECS[fault_id].summary,
                "fail_closed_expectation": CASE_SPECS[fault_id].fail_closed_expectation,
                "requires_evidence": sorted(CASE_SPECS[fault_id].requires_evidence),
                "applicable_profiles": list(CASE_SPECS[fault_id].applicable_profiles),
                "dependency_classes": list(
                    profiles.FAULT_DEPENDENCIES_BY_PROFILE[canonical_profile][fault_id]
                ),
                "compatibility_only": CASE_SPECS[fault_id].compatibility_only,
                "protocol_ref": CASE_SPECS[fault_id].protocol_ref,
                "isolation_requirement": CASE_SPECS[fault_id].isolation_requirement,
                "status": "PLANNED",
            }
            for fault_id in profile_faults
        ],
        "controller_contract": {
            "protocol": "FaultController (runtime_checkable; injected only)",
            "hooks": [
                {"hook": "capabilities", "arity": 0, "returns": "mapping with supported_faults + run-scoped isolation + read_only_preflight"},
                {"hook": "preflight", "returns": "ok + authorization_ok + checks (read-only)"},
                {"hook": "prepare", "returns": "prepared + durable prepare_ref"},
                {"hook": "apply", "returns": "applied + apply_ref (Exec-L3 action)"},
                {"hook": "observe", "returns": "observed + reason + host_admission + evidence fields"},
                {"hook": "restore", "returns": "restored + restore_ref"},
                {"hook": "reconcile", "returns": "reconciled + proof_ref (+ durable_proof)"},
                {"hook": "verify_postcondition", "returns": "ok + checks"},
            ],
            "failure_classes": ["ControllerTimeout", "ControllerDisconnect"],
            "token_rule": (
                "the controller receives the authorization in every context and "
                "MUST verify the run-scoped isolate/approval tokens itself; the "
                "driver validates structure only and never records token values"
            ),
        },
        "authorization_contract": {
            "required_fields": [
                "run_id",
                "exec_level=Exec-L3",
                "isolate_token (run-scoped)",
                "approval_token (run-scoped, distinct)",
                "allowlist (subset of the profile's registered fault ids)",
                "approved_by",
            ],
            "validation": "structural only; controller-side verification required",
        },
        "live_fault_matrix_integration": {
            "status": LIVE_FAULT_MATRIX_INTEGRATION,
            "reason": LIVE_INTEGRATION_REASON,
        },
        "offline_guarantee": (
            "this plan is produced without any I/O: no controller is contacted, "
            "no fault is applied, no file is written"
        ),
    }


# ---------------------------------------------------------------------------
# CLI: --plan / --self-test only. No flag can execute a fault.
# ---------------------------------------------------------------------------

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


def _run_self_test() -> int:
    import unittest

    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=_MODULE_DIR, pattern="test_e4_fault_driver.py", top_level_dir=_MODULE_DIR
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def _print_plan(profile: str = DEFAULT_PROFILE) -> None:
    print("E4 fault matrix plan (offline; Exec-L1; profile=" + profile + "):")
    print(LIVE_INTEGRATION_REASON)
    print("Live fault matrix integration: " + LIVE_FAULT_MATRIX_INTEGRATION)
    print("Every case below is PLANNED; no fault has been or can be applied from this CLI.")
    print(json.dumps(build_fault_plan(profile=profile), indent=2, ensure_ascii=False, sort_keys=True))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="e4_fault_driver.py",
        description=(
            "Offline-safe E4 fault-matrix protocol driver (Exec-L1). This module "
            "has no fault primitive and no network, database or service "
            "capability; only --plan and --self-test are supported. Live fault "
            "injection is Exec-L3 and requires an injected FaultController."
        ),
    )
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        choices=DEPENDENCY_PROFILES,
        help="deployment profile for the offline plan; default is native-single-node",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="print the offline fault plan (all cases PLANNED, live integration BLOCKED); no I/O",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the offline unit-test suite (test_e4_fault_driver.py) with fully fake controllers",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    _print_plan(args.profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
