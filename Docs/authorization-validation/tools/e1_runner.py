#!/usr/bin/env python3
"""Live authorization decision-path race runner.

Implements the E1 validation scenario from VALIDATION_PROTOCOL.md on top of
the shared, import-safe helpers in this directory:

- ``experiment_common``: ``stable_id`` operation identities, ``parse_authz_events``,
  ``classify_e1_allow`` interval classification, ``validate_request_terminal``,
  ``atomic_json`` / ``write_checksums`` evidence persistence.
- ``node_adapter``: signed Gateway v3 HTTP, SELECT-only SQL reconciliation,
  identifier-scoped log slices (all I/O injected; import is side-effect free).

Verified API facts this runner relies on (checked against the Rust sources in
standalone Rust workspace before coding; the runner encodes only these facts):

- ``astral-trustgraph/src/api/rules.rs``: ``GET /main/api/v1/permission-rules/check``
  takes camelCase query ``cardId``/``resourceType``/``actionCode``, requires the
  ``x-user-card-id`` context card to equal ``cardId``, and answers
  ``ApiResponse::success({"effect": "ALLOW"|"NO_MATCH"|"DENY", "reason": ...})``
  (``astral-common/src/contract/mod.rs`` envelope, payload at ``.data``).
- ``astral-trustgraph/src/api/permission_check.rs``: every ``/main/api/v1/*``
  route crosses ``permission_check_middleware``; ``GET /stats`` maps to
  resource ``monitor`` action ``read``; with the ``e1-observability`` feature the
  middleware emits ``signed_context_bound``/``decision_return``/``host_admission``
  under message ``e1 authorization observation``.
- ``policy-engine/src/engine.rs`` + ``astral-db``: candidate/final-reload events
  (``candidate_match``, ``final_reload_start``, ``evidence_load_result``,
  ``authoritative_read_start/end``, ``stable_check_end``) on the same message.
- ``astral-trustgraph/src/api/rule_sets.rs``: ``POST /rule-sets/{id}/entries``
  (camelCase entry DTO ``effect``/``resource``/``action``/``priority``, platform
  admin required, response ``data.id`` = entry id), ``DELETE
  /rule-sets/{id}/entries/{entry_id}``, ``POST /rule-sets/card/{card_id}/bind``
  (body ``{"ruleSetId":..., "refType":"BASE"}``; requires ACTIVE platform admin
  AND ``x-user-card-id == card_id``), ``DELETE
  /rule-sets/card/{card_id}/unbind/{rule_set_id}``,
  ``GET /rule-sets/card/{card_id}/bindings``.
- ``astral-trustgraph/src/repository/audit_log_repository.rs``: the
  ``x-request-id`` header is reused verbatim as the durable ``operation_id``
  (<=64 bytes of ``[A-Za-z0-9._:/-]``), written into
  ``rule_set_projection_audit`` with ``change_type`` (``DELETE``/``BIND_CARD``/
  ``UNBIND_CARD``/...), ``event_id`` and ``source_generation``.
- ``astral-trustgraph/src/repository/rule_set_repository.rs``: around the
  source-transaction commit of entry mutations the server emits
  ``source_commit_start`` / ``source_commit_end`` (``outcome`` ``committed`` or
  ``unknown``) under the mutation's ``request_id`` -- the same-process commit
  interval ``I_c`` consumed by ``experiment_common.classify_e1_allow``.
- ``authorization_delta_event`` + ``authorization_projection_current``: the
  delta chain is the durable publication record for the current Rust
  authorization path. Every relevant delta must be terminal ``SUCCEEDED`` and
  the strict aggregate pointer must be ``READY`` before the harness calls the
  publication quiescent; legacy head/outbox rows are not this predicate.

Safety contract (AGENTS.md execution gates):

- Exec-L1 offline by default: importing this module and the default CLI path
  (``plan``) performs zero node contact -- not even SQL or log reads. The only
  writes are the campaign evidence artifacts the user asked for.
- ``preflight`` is an explicit, read-only remote mode (GET + SELECT only); a
  structural ``ReadOnlyGate`` wrapper raises on any non-GET signed method.
- ``run --live`` is Exec-L3: it is opt-in through an explicit multi-factor
  HUMAN gate, never a config field: (1) ``--live`` opt-in flag, (2) a
  caller-supplied ``--approval-ref``, (3) an external ``--approval-record``
  JSON file that must match the run id, the ref, name a human approver with a
  timestamp, and carry the exact scope ``E1-LIVE-CAMPAIGN``, and (4) an
  explicit ``--confirm-exec-l3`` human confirmation flag on the command line.
  Approval can never be inferred from the run configuration alone, and passing
  the mechanical gate does NOT replace the AGENTS.md Exec-L3 user approval:
  the human final review for that specific run is still mandatory before any
  live mutation. This task ships and fake-tests the gate only; no live
  execution is performed or authorized by it.
- No real hosts, credentials, ports, or filesystem paths are embedded anywhere
  in this module; everything comes from the caller's config file.
- Durable mutations are never blindly retried: UNKNOWN outcomes are reconciled
  by stable operation id first (source row, audit correlation row, current
  RuleSet delta chain and strict pointer); a single corrective attempt is
  allowed only when reconciliation proves the mutation did not apply; otherwise
  the residual UNKNOWN is recorded and propagated (never folded into PASS).

E5 independence (verified against the current Rust sources): the middleware in
``astral-trustgraph/src/api/permission_check.rs`` emits ``decision_return`` and
then ``host_admission`` with NO admission-time watermark or pending re-read;
that is E5's subject, not E1's. This runner consumes only the E1 event chain
(signed context -> candidate match -> final reload -> stable check -> decision
-> admission) plus the mutation's same-process ``source_commit_*`` interval,
reports interval categories and stale-ALLOW violations as E1 evidence, and
never asserts an admission-time watermark, a pending re-read, or any
full-contract property derived from the E5 model check.

Python 3.8+ standard library only. Offline unit tests: ``test_e1_runner.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import experiment_common
from experiment_common import (
    EvidenceError,
    atomic_json,
    classify_e1_allow,
    events_for_request,
    mutation_commit_interval,
    parse_authz_events,
    public_provenance,
    stable_id,
    validate_request_terminal,
    write_checksums,
)
import node_adapter
from node_adapter import (
    NODE_ALIASES,
    Actor,
    AdapterError,
    ConfigError,
    NodeAdapter,
    load_config,
)

__all__ = [
    "E1Error",
    "E1Settings",
    "ReadOnlyGate",
    "execute_campaign",
    "execute_plan",
    "execute_preflight",
    "main",
]

# ---------------------------------------------------------------------------
# Verified wire constants (see module docstring for the Rust sources).
# ---------------------------------------------------------------------------

API_PREFIX = "/main/api/v1/"
STATS_PATH = API_PREFIX + "stats"
CHECK_PATH_TEMPLATE = (
    API_PREFIX
    + "permission-rules/check?cardId={card}&card_id={card}"
    + "&resourceType={resource}&actionCode={action}"
)
RULE_SET_PATH_TEMPLATE = API_PREFIX + "rule-sets/{rule_set}"
RULE_SET_ENTRIES_TEMPLATE = API_PREFIX + "rule-sets/{rule_set}/entries"
RULE_SET_ENTRY_TEMPLATE = API_PREFIX + "rule-sets/{rule_set}/entries/{entry}"
CARD_BIND_TEMPLATE = API_PREFIX + "rule-sets/card/{card}/bind"
CARD_UNBIND_TEMPLATE = API_PREFIX + "rule-sets/card/{card}/unbind/{rule_set}"
CARD_BINDINGS_TEMPLATE = API_PREFIX + "rule-sets/card/{card}/bindings"

#: E1 mutates RuleSet entries and bindings. Their authorization deltas publish
#: under the RuleSet aggregate; the resulting strict pointer is card-scoped via
#: its ``card_id`` field and is consumed by the published-card reader. Direct
#: ``USER_CARD`` deltas belong to the separate permission-rule path and are not
#: evidence of this campaign's source mutation.
AGGREGATE_RULE_SET = "RULE_SET"
POINTER_STATUS_READY = "READY"
DELTA_STATUS_SUCCEEDED = "SUCCEEDED"
DELTA_EVENT_REMOVE = "REMOVE"
AUDIT_CHANGE_TYPE_DELETE = "DELETE"

#: Effect vocabulary of ``/permission-rules/check`` (``.data.effect``).
CHECK_EFFECT_ALLOW = "ALLOW"
PRE_GRANT_SAFE_EFFECTS = frozenset({"DENY", "NO_MATCH"})

#: The only mutation verbs this runner may ever issue.
_MUTATION_METHODS = frozenset({"POST", "DELETE"})
_ENTRY_EFFECT = "ALLOW"

_SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_POSITIVE_I64_TEXT_RE = re.compile(r"^[1-9][0-9]{0,18}$")
_MAX_SIGNED_I64 = (1 << 63) - 1
_APPROVAL_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_ISO_DATETIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?$")

MAX_CYCLES = 64
MAX_READERS = 8
MAX_REQUESTS_PER_READER = 200
MAX_RECONCILE_POLLS = 120
READER_JOIN_TIMEOUT_S = 30.0

#: Status aggregation severity (worst wins; fixed order).
_STATUS_SEVERITY = {
    "PASS": 0,
    "SKIP": 1,
    "PENDING": 2,
    "BLOCKED": 3,
    "UNKNOWN": 4,
    "FAIL": 5,
}


class E1Error(RuntimeError):
    """A campaign-safety or evidence-integrity violation (constant labels only)."""


# ---------------------------------------------------------------------------
# Immutable per-cycle result container.
# ---------------------------------------------------------------------------


class FrozenResult(dict):
    """A result dict that becomes immutable once frozen.

    Per-cycle evidence is computed exactly once and must never be rewritten by
    later phases (protocol: immutable per-cycle result); silent status repair
    or reclassification is a hard error.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._frozen = False

    def freeze(self) -> "FrozenResult":
        object.__setattr__(self, "_frozen", True)
        return self

    @property
    def frozen(self) -> bool:
        return self._frozen

    def _guard(self) -> None:
        if self._frozen:
            raise E1Error("cycle result is frozen; per-cycle evidence is immutable")

    def __setitem__(self, key: str, value: Any) -> None:
        self._guard()
        super().__setitem__(key, value)

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        self._guard()
        super().update(*args, **kwargs)

    def setdefault(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        self._guard()
        return super().setdefault(key, default)

    def __delitem__(self, key: str) -> None:
        self._guard()
        super().__delitem__(key)

    def pop(self, key: str, *args: Any) -> Any:  # type: ignore[override]
        self._guard()
        return super().pop(key, *args)

    def popitem(self) -> Tuple[str, Any]:  # type: ignore[override]
        self._guard()
        return super().popitem()

    def clear(self) -> None:
        self._guard()
        super().clear()

    def __ior__(self, other: Mapping[str, Any]) -> "FrozenResult":
        self._guard()
        super().__ior__(other)
        return self


def worst_status(statuses: Sequence[str]) -> str:
    """Worst evidence status by the fixed severity order; empty means BLOCKED."""
    if not statuses:
        return "BLOCKED"
    for value in statuses:
        if value not in _STATUS_SEVERITY:
            raise E1Error("unknown evidence status in aggregation")
    return max(sorted(statuses), key=lambda value: _STATUS_SEVERITY[value])


# ---------------------------------------------------------------------------
# Configuration: a flattened run_config mapping plus an "e1" section.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class E1Settings:
    """Validated, campaign-specific settings (safe metadata only)."""

    run_id: str
    card_id: int
    rule_set_id: int
    tenant_id: int
    resource_type: str
    action_code: str
    ref_type: str
    cycles: int
    readers: int
    max_requests_per_reader: int
    node_rotation: Tuple[str, ...]
    fixture_synthetic: bool
    reconcile_polls: int
    reconcile_interval_s: float

    def public_metadata(self) -> Dict[str, Any]:
        return {
            "runId": self.run_id,
            "cardId": self.card_id,
            "ruleSetId": self.rule_set_id,
            "tenantId": self.tenant_id,
            "resourceType": self.resource_type,
            "actionCode": self.action_code,
            "refType": self.ref_type,
            "cycles": self.cycles,
            "readers": self.readers,
            "maxRequestsPerReader": self.max_requests_per_reader,
            "nodeRotation": list(self.node_rotation),
            "fixtureSynthetic": self.fixture_synthetic,
            "reconcilePolls": self.reconcile_polls,
            "reconcileIntervalS": self.reconcile_interval_s,
        }


def _bounded_int(raw: Mapping[str, Any], key: str, *, low: int, high: int) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(["invalid:e1.%s" % key])
    return int(value)


def _bounded_float(raw: Mapping[str, Any], key: str, *, low: float, high: float) -> float:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise ConfigError(["invalid:e1.%s" % key])
    return float(value)


def _validate_e1_section(raw: Mapping[str, Any]) -> E1Settings:
    e1 = raw.get("e1")
    if not isinstance(e1, Mapping):
        raise ConfigError(["missing:e1"])
    problems: List[str] = []

    allowlist = e1.get("allowlist")
    if not isinstance(allowlist, Mapping):
        raise ConfigError(["missing:e1.allowlist"])
    card_id = allowlist.get("card_id")
    rule_set_id = allowlist.get("rule_set_id")
    for name, value in (("card_id", card_id), ("rule_set_id", rule_set_id)):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            problems.append("invalid:e1.allowlist.%s" % name)
    resource_type = allowlist.get("resource_type")
    action_code = allowlist.get("action_code")
    for name, value in (("resource_type", resource_type), ("action_code", action_code)):
        if not isinstance(value, str) or not _SAFE_NAME_RE.fullmatch(value):
            problems.append("invalid:e1.allowlist.%s" % name)
    ref_type = allowlist.get("ref_type")
    if ref_type != "BASE":
        problems.append("invalid:e1.allowlist.ref_type")
    if problems:
        raise ConfigError(sorted(set(problems)))

    actor_raw = e1.get("admin_actor")
    if not isinstance(actor_raw, Mapping):
        raise ConfigError(["missing:e1.admin_actor"])
    try:
        actor = Actor.from_mapping(actor_raw)
    except (TypeError, ValueError) as error:
        raise ConfigError(["invalid:e1.admin_actor:%s" % type(error).__name__]) from error
    # bind / check / unbind all require x-user-card-id == path card; the admin
    # actor therefore must carry the fixture card as its user card.
    if actor.user_card != str(card_id):
        raise ConfigError(["invalid:e1.admin_actor.card_must_equal_allowlist_card_id"])
    if not _POSITIVE_I64_TEXT_RE.fullmatch(actor.tenant):
        raise ConfigError(["invalid:e1.admin_actor.tenant"])
    tenant_id = int(actor.tenant)
    if tenant_id > _MAX_SIGNED_I64:
        raise ConfigError(["invalid:e1.admin_actor.tenant"])

    rotation = e1.get("node_rotation")
    if (
        not isinstance(rotation, list)
        or not rotation
        or any(node not in NODE_ALIASES for node in rotation)
        or len(set(rotation)) != len(rotation)
    ):
        raise ConfigError(["invalid:e1.node_rotation"])

    fixture_synthetic = e1.get("fixture_synthetic")
    if not isinstance(fixture_synthetic, bool):
        raise ConfigError(["invalid:e1.fixture_synthetic"])

    return E1Settings(
        run_id=str(raw["run_id"]),
        card_id=int(card_id),
        rule_set_id=int(rule_set_id),
        tenant_id=tenant_id,
        resource_type=str(resource_type),
        action_code=str(action_code),
        ref_type=str(ref_type),
        cycles=_bounded_int(e1, "cycles", low=1, high=MAX_CYCLES),
        readers=_bounded_int(e1, "readers", low=1, high=MAX_READERS),
        max_requests_per_reader=_bounded_int(
            e1, "max_requests_per_reader", low=1, high=MAX_REQUESTS_PER_READER
        ),
        node_rotation=tuple(str(node) for node in rotation),
        fixture_synthetic=bool(fixture_synthetic),
        reconcile_polls=_bounded_int(e1, "reconcile_polls", low=1, high=MAX_RECONCILE_POLLS),
        reconcile_interval_s=_bounded_float(e1, "reconcile_interval_s", low=0.0, high=10.0),
    )


def load_e1_config(raw: Mapping[str, Any]) -> Tuple[node_adapter.NodeAdapterConfig, E1Settings]:
    """Validate the full run config (flat mapping + e1 section); no I/O."""
    adapter_config = load_config(raw)
    settings = _validate_e1_section(raw)
    return adapter_config, settings


# ---------------------------------------------------------------------------
# Operation identities (<=64 bytes; stable via experiment_common.stable_id).
# ---------------------------------------------------------------------------

#: Mutation order per cycle: the grant is added BEFORE it is bound.
OP_ORDER = ("addEntry", "bind", "deleteEntry", "unbind")


def operation_ids_for_cycle(run_id: str, cycle: int) -> Dict[str, str]:
    """Deterministic per-cycle mutation operation ids (add before bind)."""
    labels = {
        "addEntry": "e1:c%d:add-entry" % cycle,
        "bind": "e1:c%d:bind" % cycle,
        "deleteEntry": "e1:c%d:delete-entry" % cycle,
        "unbind": "e1:c%d:unbind" % cycle,
    }
    return {name: stable_id(run_id, label) for name, label in labels.items()}


def reader_request_id(run_id: str, cycle: int, reader: int, sequence: int) -> str:
    """Unique per-request id for one bounded reader attempt."""
    return stable_id(run_id, "e1:c%d:r%d:n%d" % (cycle, reader, sequence))


def check_path(settings: E1Settings) -> str:
    return CHECK_PATH_TEMPLATE.format(
        card=settings.card_id, resource=settings.resource_type, action=settings.action_code
    )


def _entry_body(settings: E1Settings) -> Dict[str, Any]:
    return {
        "effect": _ENTRY_EFFECT,
        "resource": settings.resource_type,
        "action": settings.action_code,
        "priority": 100,
    }


def _bind_body(settings: E1Settings) -> Dict[str, Any]:
    return {"ruleSetId": settings.rule_set_id, "refType": settings.ref_type}


# ---------------------------------------------------------------------------
# Structural read-only gate used by preflight (GET + SELECT only).
# ---------------------------------------------------------------------------


class ReadOnlyGate:
    """Wrapper that makes mutation attempts structurally impossible."""

    def __init__(self, adapter: NodeAdapter) -> None:
        self._adapter = adapter

    def signed_get(
        self,
        node: str,
        path: str,
        actor: Optional[Actor] = None,
        *,
        request_id: Optional[str] = None,
        timeout_s: float = 30.0,
    ) -> Tuple[int, Dict[str, Any], str]:
        return self._adapter.signed_get(
            node, path, actor, request_id=request_id, timeout_s=timeout_s
        )

    def signed_request(self, *args: Any, **kwargs: Any) -> Any:
        raise E1Error("read_only_gate: signed mutations are not permitted during preflight")

    def sql(self, query: str, *, timeout_s: float = 60.0) -> List[List[str]]:
        return self._adapter.sql(query, timeout_s=timeout_s)

    def head_state(self, aggregate_type: str, aggregate_id: int) -> List[List[str]]:
        return self._adapter.head_state(aggregate_type, aggregate_id)

    def delta_states(
        self, tenant_id: int, aggregate_type: str, aggregate_id: int
    ) -> List[List[str]]:
        return self._adapter.delta_states(tenant_id, aggregate_type, aggregate_id)

    def delta_rows_for_operation(
        self, tenant_id: int, aggregate_type: str, aggregate_id: int, operation_id: str
    ) -> List[List[str]]:
        return self._adapter.delta_rows_for_operation(
            tenant_id, aggregate_type, aggregate_id, operation_id
        )

    def outbox_rows(self, aggregate_type: str, aggregate_id: int) -> List[List[str]]:
        return self._adapter.outbox_rows(aggregate_type, aggregate_id)

    def projection_pointer(
        self, tenant_id: int, aggregate_type: str, aggregate_id: int
    ) -> List[List[str]]:
        return self._adapter.projection_pointer(tenant_id, aggregate_type, aggregate_id)

    def read_log_lines(
        self, node: str, identifiers: Sequence[str], *, timeout_s: float = 120.0
    ) -> List[str]:
        return self._adapter.read_log_lines(node, identifiers, timeout_s=timeout_s)


# ---------------------------------------------------------------------------
# Mutation helper (one bounded attempt; never retries internally).
# ---------------------------------------------------------------------------


def issue_mutation(
    adapter: NodeAdapter,
    node: str,
    method: str,
    path: str,
    body: Optional[Mapping[str, Any]],
    op_id: str,
    *,
    clock_ns: Optional[Callable[[], int]] = None,
) -> Dict[str, Any]:
    """Issue exactly one signed mutation attempt under a stable operation id.

    Outcome vocabulary: ``committed`` (HTTP 200), ``rejected`` (definitive 4xx),
    ``unknown`` (5xx, transport failure, or no status). The client-side wall
    interval is auxiliary metadata; the authoritative commit interval is the
    server-side ``source_commit_*`` events correlated by ``op_id``.
    """
    if method not in _MUTATION_METHODS:
        raise E1Error("mutation method outside allowlist")
    tick = clock_ns if clock_ns is not None else (lambda: time.time_ns())
    started_ns = tick()
    http_status: Optional[int] = None
    response_body: Optional[Mapping[str, Any]] = None
    error_class: Optional[str] = None
    try:
        status, parsed, _request_id = adapter.signed_request(
            node, method, path, dict(body) if body is not None else None, request_id=op_id
        )
        http_status = int(status)
        response_body = parsed
    except (AdapterError, OSError, ValueError) as error:
        error_class = type(error).__name__
    ended_ns = tick()
    if error_class is not None or http_status is None:
        outcome = "unknown"
    elif http_status == 200:
        outcome = "committed"
    elif 400 <= http_status < 500:
        outcome = "rejected"
    else:
        outcome = "unknown"
    return {
        "opId": op_id,
        "node": node,
        "method": method,
        "path": path,
        "httpStatus": http_status,
        "outcome": outcome,
        "errorClass": error_class,
        "startedNs": int(started_ns),
        "endedNs": int(ended_ns),
        "responseData": (
            dict(response_body)
            if outcome == "committed" and isinstance(response_body, Mapping)
            else None
        ),
    }


# ---------------------------------------------------------------------------
# Read-only durable reconciliation (SELECT-only + admin GETs).
# ---------------------------------------------------------------------------


def _tsv_scalar(rows: Sequence[Sequence[str]]) -> Optional[str]:
    if len(rows) == 1 and len(rows[0]) == 1:
        return rows[0][0]
    return None


def entry_row_count(
    adapter: NodeAdapter, tenant_id: int, rule_set_id: int, entry_id: int
) -> Optional[int]:
    """Tenant-scoped source-row existence probe for one entry (SELECT-only)."""
    query = (
        "SELECT COUNT(*) FROM rule_set_entry rse "
        "INNER JOIN rule_set rs ON rs.rule_set_id=rse.rule_set_id "
        "WHERE rs.tenant_id=%d AND rse.entry_id=%d AND rse.rule_set_id=%d"
        % (int(tenant_id), int(entry_id), int(rule_set_id))
    )
    try:
        value = _tsv_scalar(adapter.sql(query))
    except (AdapterError, ValueError, OSError):
        return None
    if value is None or not value.isdigit():
        return None
    return int(value)


def active_tenant_rule_set_count(
    adapter: NodeAdapter, tenant_id: int, rule_set_id: int
) -> Optional[int]:
    """Count active RuleSets owned by the signed tenant (SELECT-only).

    E1 never treats a tenantless or cross-tenant RuleSet as a usable fixture.
    ``rule_set_entry.tenant_id`` is not the ownership source, so this check and
    the entry probe both derive scope from the RuleSet owner row.
    """
    query = (
        "SELECT COUNT(*) FROM rule_set "
        "WHERE rule_set_id=%d AND tenant_id=%d AND enabled=1"
        % (int(rule_set_id), int(tenant_id))
    )
    try:
        value = _tsv_scalar(adapter.sql(query))
    except (AdapterError, ValueError, OSError):
        return None
    if value is None or not value.isdigit():
        return None
    return int(value)


def fetch_audit_rows(
    adapter: NodeAdapter, tenant_id: int, op_id: str
) -> Optional[List[Dict[str, Any]]]:
    """Audit-correlation rows for one stable operation id (SELECT-only).

    Returns ``None`` when the read itself fails (UNKNOWN); a missing read is
    never evidence of absence.
    """
    if not experiment_common.SAFE_ID.fullmatch(op_id):
        raise E1Error("audit correlation id must match the safe identifier alphabet")
    query = (
        "SELECT rule_set_id, IFNULL(entry_id,0), aggregate_type, aggregate_id, "
        "change_type, event_id, source_generation "
        "FROM rule_set_projection_audit "
        "WHERE tenant_id=%d AND operation_id='%s' ORDER BY source_generation, event_id"
        % (int(tenant_id), op_id)
    )
    try:
        rows = adapter.sql(query)
    except (AdapterError, ValueError, OSError):
        return None
    parsed: List[Dict[str, Any]] = []
    for row in rows:
        if len(row) != 7:
            return None
        (
            rule_set_value,
            entry_value,
            aggregate_type,
            aggregate_value,
            change_type,
            event_id,
            generation_value,
        ) = row
        parsed.append(
            {
                "ruleSetId": int(rule_set_value) if rule_set_value.isdigit() else None,
                "entryId": int(entry_value) if entry_value.isdigit() else None,
                "aggregateType": aggregate_type,
                "aggregateId": int(aggregate_value) if aggregate_value.isdigit() else None,
                "changeType": change_type,
                "eventId": event_id,
                "sourceGeneration": (
                    int(generation_value) if generation_value.isdigit() else None
                ),
            }
        )
    return parsed


def bindings_contain(
    adapter: NodeAdapter, node: str, card_id: int, rule_set_id: int
) -> Optional[bool]:
    """Read-only admin probe whether the card is bound to the rule set."""
    try:
        status, body, _ = adapter.signed_get(
            node, CARD_BINDINGS_TEMPLATE.format(card=card_id)
        )
    except (AdapterError, OSError, ValueError):
        return None
    if status != 200:
        return None
    data = body.get("data")
    if not isinstance(data, list):
        return None
    for row in data:
        if isinstance(row, Mapping) and row.get("ruleSetId") == rule_set_id:
            return True
    return False


def _parse_generation(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def projection_snapshot(
    adapter: Any, tenant_id: int, aggregate_type: str, aggregate_id: int
) -> Dict[str, Any]:
    """Read-only delta-chain publication snapshot for one aggregate.

    Publication completeness on the tenant-scoped delta chain requires every
    delta event to be ``SUCCEEDED`` and the strict pointer to be ``READY``.
    ``target_version`` is per-grant lineage metadata and is recorded for
    diagnostics only; it is not compared with the pointer generation.
    """
    snapshot: Dict[str, Any] = {
        "tenantId": tenant_id,
        "aggregateType": aggregate_type,
        "aggregateId": aggregate_id,
    }
    try:
        delta_rows = adapter.delta_states(tenant_id, aggregate_type, aggregate_id)
        pointer_rows = adapter.projection_pointer(tenant_id, aggregate_type, aggregate_id)
    except (AdapterError, OSError, ValueError) as error:
        snapshot["state"] = "unknown"
        snapshot["problems"] = [type(error).__name__]
        return snapshot
    snapshot["deltaRows"] = len(delta_rows)
    statuses: List[str] = []
    max_target: Optional[int] = None
    non_terminal: List[int] = []
    malformed_delta_rows: List[int] = []
    for index, row in enumerate(delta_rows):
        if len(row) != 2:
            malformed_delta_rows.append(index)
            continue
        status_value, target_value = row[0], row[1]
        target = _parse_generation(target_value)
        if not status_value or target is None or target <= 0:
            malformed_delta_rows.append(index)
            continue
        statuses.append(status_value)
        if max_target is None or target > max_target:
            max_target = target
        if status_value != DELTA_STATUS_SUCCEEDED:
            non_terminal.append(target)
    snapshot["deltaStatuses"] = sorted(set(statuses))
    snapshot["maxTargetVersion"] = max_target
    snapshot["nonTerminalTargets"] = sorted(set(non_terminal))
    if malformed_delta_rows:
        snapshot["state"] = "unknown"
        snapshot["problems"] = ["malformed_delta_rows"]
        snapshot["malformedDeltaRows"] = malformed_delta_rows
        return snapshot
    pointer_status: Optional[str] = None
    pointer_generation: Optional[int] = None
    if len(pointer_rows) > 1:
        snapshot["state"] = "unknown"
        snapshot["problems"] = ["multiple_projection_pointers"]
        return snapshot
    if pointer_rows:
        pointer_row = pointer_rows[0]
        if len(pointer_row) != 7:
            snapshot["state"] = "unknown"
            snapshot["problems"] = ["malformed_projection_pointer"]
            return snapshot
        pointer_generation = _parse_generation(pointer_row[0])
        pointer_status = pointer_row[1]
        pointer_fence = _parse_generation(pointer_row[2])
        pointer_cas = _parse_generation(pointer_row[3])
        pointer_event_id = pointer_row[4]
        pointer_operation_id = pointer_row[5]
        pointer_card_id = _parse_generation(pointer_row[6])
        if (
            pointer_generation is None
            or pointer_generation <= 0
            or not pointer_status
            or pointer_fence is None
            or pointer_fence < 0
            or pointer_cas is None
            or pointer_cas < 0
            or not pointer_event_id
            or not pointer_operation_id
            or pointer_card_id is None
            or pointer_card_id <= 0
        ):
            snapshot["state"] = "unknown"
            snapshot["problems"] = ["malformed_projection_pointer"]
            return snapshot
        snapshot["pointerEventId"] = pointer_event_id
        snapshot["pointerOperationId"] = pointer_operation_id
        snapshot["pointerCardId"] = pointer_card_id
    snapshot["pointerStatus"] = pointer_status
    snapshot["pointerGeneration"] = pointer_generation
    # Publication completeness: every delta of the aggregate is SUCCEEDED and
    # the tenant-scoped strict pointer is READY. target_version is per-lineage
    # (it restarts across entry generations), so pointer==max(target) is not a
    # valid equality -- the pointer's monotone CAS is the projector contract.
    quiescent = (
        bool(delta_rows)
        and not non_terminal
        and pointer_status == POINTER_STATUS_READY
    )
    snapshot["state"] = "quiescent" if quiescent else "not_quiescent"
    return snapshot


def wait_projection_quiescent(
    adapter: Any,
    tenant_id: int,
    targets: Sequence[Tuple[str, int]],
    *,
    attempts: int = 30,
    interval_s: float = 1.0,
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Bounded read-only wait until every aggregate snapshot is quiescent."""
    snapshots: List[Dict[str, Any]] = []
    for index in range(max(1, attempts)):
        snapshots = [
            projection_snapshot(adapter, tenant_id, agg, agg_id)
            for agg, agg_id in targets
        ]
        if all(snapshot.get("state") == "quiescent" for snapshot in snapshots):
            return True, snapshots
        if index < attempts - 1 and interval_s > 0:
            time.sleep(interval_s)
    return False, snapshots


def operation_delete_publication(
    adapter: Any,
    tenant_id: int,
    rule_set_id: int,
    card_id: int,
    op_id: str,
    pointer_snapshot: Mapping[str, Any],
) -> Dict[str, Any]:
    """Read operation-attributed RuleSet publication evidence (SELECT-only).

    The E1 fixture has exactly one bound card and one materializable ALLOW entry
    at delete time. Its delete operation must therefore yield exactly one
    ``REMOVE`` delta for that card, and the aggregate snapshot's strict pointer
    must name the same event and operation. Aggregate quiescence alone cannot
    establish this association because older terminal deltas remain visible.
    """
    evidence: Dict[str, Any] = {
        "operationId": op_id,
        "expectedCardId": card_id,
        "deltaRows": None,
        "pointerMatchesOperation": False,
    }
    try:
        rows = adapter.delta_rows_for_operation(
            tenant_id, AGGREGATE_RULE_SET, rule_set_id, op_id
        )
    except (AdapterError, OSError, ValueError) as error:
        evidence["reason"] = "operation_delta_read_failed:%s" % type(error).__name__
        return evidence
    evidence["deltaRows"] = len(rows)
    if len(rows) != 1:
        evidence["reason"] = "operation_delta_cardinality_mismatch"
        return evidence
    row = rows[0]
    if len(row) != 5:
        evidence["reason"] = "malformed_operation_delta"
        return evidence
    event_id, event_type, status, target_value, card_value = row
    target = _parse_generation(target_value)
    delta_card_id = _parse_generation(card_value)
    if (
        not event_id
        or event_type != DELTA_EVENT_REMOVE
        or status != DELTA_STATUS_SUCCEEDED
        or target is None
        or target <= 0
        or delta_card_id != card_id
    ):
        evidence["reason"] = "operation_delta_not_terminal_or_scope_mismatch"
        return evidence
    evidence["delta"] = {
        "eventId": event_id,
        "status": status,
        "targetVersion": target,
        "cardId": delta_card_id,
        "eventType": event_type,
    }
    pointer_status = pointer_snapshot.get("pointerStatus")
    pointer_event_id = pointer_snapshot.get("pointerEventId")
    pointer_op_id = pointer_snapshot.get("pointerOperationId")
    pointer_card_id = pointer_snapshot.get("pointerCardId")
    evidence["pointer"] = {
        "generation": pointer_snapshot.get("pointerGeneration"),
        "status": pointer_status,
        "eventId": pointer_event_id,
        "operationId": pointer_op_id,
        "cardId": pointer_card_id,
    }
    if (
        pointer_snapshot.get("state") == "unknown"
        or pointer_status != POINTER_STATUS_READY
        or pointer_card_id != card_id
        or pointer_event_id != event_id
        or pointer_op_id != op_id
    ):
        evidence["reason"] = "operation_pointer_does_not_match_delta"
        return evidence
    evidence["pointerMatchesOperation"] = True
    return evidence


def wait_delete_publication(
    adapter: Any,
    tenant_id: int,
    rule_set_id: int,
    card_id: int,
    op_id: str,
    *,
    attempts: int,
    interval_s: float,
) -> Tuple[bool, Dict[str, Any], List[Dict[str, Any]]]:
    """Bounded read-only wait for this delete operation's published delta."""
    operation: Dict[str, Any] = {
        "operationId": op_id,
        "pointerMatchesOperation": False,
        "reason": "operation_publication_not_observed",
    }
    snapshots: List[Dict[str, Any]] = []
    for index in range(max(1, attempts)):
        snapshot = projection_snapshot(adapter, tenant_id, AGGREGATE_RULE_SET, rule_set_id)
        snapshots = [snapshot]
        operation = operation_delete_publication(
            adapter, tenant_id, rule_set_id, card_id, op_id, snapshot
        )
        if snapshot.get("state") == "quiescent" and operation.get("pointerMatchesOperation"):
            return True, operation, snapshots
        if index < attempts - 1 and interval_s > 0:
            time.sleep(interval_s)
    return False, operation, snapshots


def reconcile_delete_entry(
    adapter: Any,
    tenant_id: int,
    card_id: int,
    rule_set_id: int,
    entry_id: int,
    op_id: str,
    *,
    attempts: int = 1,
    interval_s: float = 0.0,
) -> Dict[str, Any]:
    """Reconcile one ``deleteEntry`` mutation by its stable operation id.

    States: ``applied`` (source row gone, DELETE audit row present, this
    operation's unique ``REMOVE`` delta published by the matching strict
    pointer, and aggregate tail quiescent), ``not_applied`` (row still present
    AND no audit row; a single corrective attempt is then provably safe), else
    ``unknown`` (never retried; recorded as residual UNKNOWN).
    """
    audit_rows = fetch_audit_rows(adapter, tenant_id, op_id)
    source_count = entry_row_count(adapter, tenant_id, rule_set_id, entry_id)
    result: Dict[str, Any] = {
        "opId": op_id,
        "auditRows": None,
        "sourceRowCount": source_count,
    }
    if audit_rows is None or source_count is None:
        result["state"] = "unknown"
        result["reason"] = "reconciliation_read_failed"
        return result
    result["auditRows"] = audit_rows
    delete_rows = [
        row
        for row in audit_rows
        if row.get("changeType") == AUDIT_CHANGE_TYPE_DELETE
        and row.get("ruleSetId") == rule_set_id
        and row.get("entryId") == entry_id
        and row.get("aggregateType") == AGGREGATE_RULE_SET
        and row.get("aggregateId") == rule_set_id
    ]
    result["matchingDeleteAuditRows"] = len(delete_rows)
    if source_count == 0 and len(delete_rows) == 1:
        published, operation_publication, snapshots = wait_delete_publication(
            adapter,
            tenant_id,
            rule_set_id,
            card_id,
            op_id,
            attempts=attempts,
            interval_s=interval_s,
        )
        result["operationPublication"] = operation_publication
        result["projection"] = snapshots
        if published:
            result["state"] = "applied"
        else:
            result["state"] = "unknown"
            result["reason"] = "operation_publication_unproven_after_delete"
        return result
    if source_count > 0 and not audit_rows:
        result["state"] = "not_applied"
        return result
    result["state"] = "unknown"
    result["reason"] = "contradictory_or_missing_reconciliation_evidence"
    return result


def reconcile_add_entry(adapter: Any, tenant_id: int, op_id: str) -> Dict[str, Any]:
    """Reconcile one ``addEntry`` mutation by its audit correlation row."""
    audit_rows = fetch_audit_rows(adapter, tenant_id, op_id)
    if audit_rows is None:
        return {"opId": op_id, "state": "unknown", "reason": "reconciliation_read_failed"}
    with_entry = [row for row in audit_rows if row.get("entryId")]
    if with_entry:
        return {
            "opId": op_id,
            "state": "applied",
            "entryId": int(with_entry[-1]["entryId"]),
            "auditRows": audit_rows,
        }
    if not audit_rows:
        return {"opId": op_id, "state": "not_applied", "auditRows": []}
    return {"opId": op_id, "state": "unknown", "reason": "audit_row_without_entry_id"}


# ---------------------------------------------------------------------------
# E1 log parsing and classification (same-process events only).
# ---------------------------------------------------------------------------


def build_mutation_evidence(
    events: Sequence[experiment_common.Event], delete_op_id: str
) -> Dict[str, Any]:
    """Server-side commit interval for the delete op (same process log)."""
    mutation_events = events_for_request(events, delete_op_id)
    evidence: Dict[str, Any] = {
        "requestId": delete_op_id,
        "events": len(mutation_events),
        "commitIntervalProven": False,
        "commitInterval": None,
        "problems": [],
    }
    if not mutation_events:
        evidence["problems"].append("no_server_events_for_delete_operation")
        return evidence
    try:
        commit = mutation_commit_interval(mutation_events)
        evidence["commitInterval"] = {"start": commit.start, "end": commit.end}
        evidence["commitIntervalProven"] = True
    except EvidenceError as error:
        evidence["problems"].append(str(error))
    return evidence


def _event_candidate_identity(event: experiment_common.Event) -> Tuple[Any, ...]:
    fields = ("tenant_id", "card_id", "grant_id", "grant_revision", "grant_hash")
    values = tuple(event.fields.get(field) for field in fields)
    if any(value in (None, "") for value in values):
        raise EvidenceError("candidate event lacks exact grant identity")
    return values


def classify_reader_requests(
    events: Sequence[experiment_common.Event],
    reader_attempts: Sequence[Mapping[str, Any]],
    delete_op_id: str,
    expected_candidate_identity: Optional[Tuple[Any, ...]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Classify each reader request exactly once (immutable evidence).

    ALLOW (HTTP 200) requests are classified by
    ``experiment_common.classify_e1_allow`` against the delete op's
    same-process commit interval; every classification failure degrades to an
    explicit ``unclassified-unknown`` row, never to a merged zero.
    """
    mutation_events = events_for_request(events, delete_op_id)
    mutation = build_mutation_evidence(events, delete_op_id)
    rows: List[Dict[str, Any]] = []
    for attempt in reader_attempts:
        request_id = str(attempt.get("requestId") or "")
        http_status = attempt.get("httpStatus")
        row: Dict[str, Any] = {
            "requestId": request_id,
            "httpStatus": http_status,
            "decision": None,
            "category": None,
            "theoremDomain": False,
            "staleAllowViolation": False,
            "problems": [],
        }
        request_events = events_for_request(events, request_id)
        if not request_events:
            row["problems"].append("no_server_events_for_request")
            if attempt.get("error"):
                row["problems"].append(str(attempt["error"]))
            row["decision"] = "UNKNOWN"
            rows.append(row)
            continue
        if http_status == 200:
            row["decision"] = "ALLOW"
            if not mutation["commitIntervalProven"]:
                row["problems"].append("missing_server_commit_interval")
                row["category"] = "unclassified-unknown"
            else:
                try:
                    verdict = classify_e1_allow(request_events, mutation_events)
                    row["category"] = verdict["category"]
                    row["theoremDomain"] = bool(verdict["theoremDomain"])
                    row["staleAllowViolation"] = bool(verdict["staleAllowViolation"])
                    row["evidenceSource"] = verdict["evidenceSource"]
                    row["commitInterval"] = verdict["commitInterval"]
                    row["finalObservationInterval"] = verdict["finalObservationInterval"]
                    if expected_candidate_identity is None:
                        row["problems"].append("e0_identity_unproven")
                        row["category"] = "unclassified-unknown"
                        row["staleAllowViolation"] = False
                    else:
                        observed_identity = _event_candidate_identity(
                            experiment_common.one_event(request_events, "candidate_match")
                        )
                        row["candidateMatchesE0"] = observed_identity == expected_candidate_identity
                        if observed_identity != expected_candidate_identity:
                            row["problems"].append("candidate_identity_does_not_match_e0")
                            row["category"] = "unclassified-unknown"
                            row["staleAllowViolation"] = False
                except EvidenceError as error:
                    row["problems"].append(str(error))
                    row["category"] = "unclassified-unknown"
        elif http_status is None:
            row["decision"] = "UNKNOWN"
            row["problems"].append(str(attempt.get("error") or "transport_error"))
        else:
            try:
                terminal = validate_request_terminal(request_events, int(http_status))
                row["decision"] = terminal["decision"]
                row["reason"] = terminal["reason"]
            except (EvidenceError, TypeError, ValueError) as error:
                row["decision"] = "UNKNOWN"
                row["problems"].append(
                    str(error) if isinstance(error, EvidenceError) else "invalid_http_status"
                )
        rows.append(row)
    return rows, mutation


# ---------------------------------------------------------------------------
# Preflight (read-only; GET + SELECT only, enforced by ReadOnlyGate).
# ---------------------------------------------------------------------------


def _check_entry(label: str, ok: bool, detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"check": label, "status": "PASS" if ok else "FAIL"}
    if detail:
        entry["detail"] = detail
    return entry


def _signed_get_checked(
    gate: Any, node: str, path: str, op_id: str
) -> Tuple[str, Optional[int], Optional[Mapping[str, Any]], List[str]]:
    """One GET with a pinned request id; returns (label, http, data, problems)."""
    try:
        status, body, _ = gate.signed_get(node, path, request_id=op_id)
    except (AdapterError, OSError, ValueError) as error:
        return "transport_error", None, None, ["transport:%s" % type(error).__name__]
    if status != 200:
        return "http_%s" % status, status, None, []
    data = body.get("data") if isinstance(body, Mapping) else None
    if not isinstance(data, Mapping) and not isinstance(data, list):
        return "bad_envelope", status, None, ["response_data_missing"]
    return "ok", status, data, []


def run_preflight_checks(gate: Any, settings: E1Settings, node: str) -> Dict[str, Any]:
    """All E1 preconditions; every failure blocks the campaign before writes."""
    checks: List[Dict[str, Any]] = []
    smoke_request_id = stable_id(settings.run_id, "e1:preflight:smoke")
    check_request_id = stable_id(settings.run_id, "e1:preflight:check")
    anchor_request_id = stable_id(settings.run_id, "e1:preflight:anchor")
    entries_request_id = stable_id(settings.run_id, "e1:preflight:entries")
    bindings_request_id = stable_id(settings.run_id, "e1:preflight:bindings")
    stats_request_id = stable_id(settings.run_id, "e1:preflight:stats")

    checks.append(
        _check_entry(
            "fixture_synthetic_attestation",
            settings.fixture_synthetic,
            None
            if settings.fixture_synthetic
            else {"reason": "config must attest the fixture is an isolated synthetic"},
        )
    )

    label, status, data, problems = _signed_get_checked(
        gate, node, RULE_SET_PATH_TEMPLATE.format(rule_set=settings.rule_set_id), anchor_request_id
    )
    checks.append(
        _check_entry(
            "rule_set_anchor",
            isinstance(data, Mapping) and data.get("id") == settings.rule_set_id and label == "ok",
            {"httpStatus": status, "ruleSetId": settings.rule_set_id, "problems": problems},
        )
    )

    try:
        active_tenant_rule_set = active_tenant_rule_set_count(
            gate, settings.tenant_id, settings.rule_set_id
        )
    except (AdapterError, OSError, ValueError):
        active_tenant_rule_set = None
    checks.append(
        _check_entry(
            "rule_set_owned_by_active_tenant",
            active_tenant_rule_set == 1,
            {
                "tenantId": settings.tenant_id,
                "ruleSetId": settings.rule_set_id,
                "matchingRuleSetCount": active_tenant_rule_set,
            },
        )
    )

    label, status, entries_data, problems = _signed_get_checked(
        gate,
        node,
        RULE_SET_ENTRIES_TEMPLATE.format(rule_set=settings.rule_set_id),
        entries_request_id,
    )
    entries = entries_data if isinstance(entries_data, list) else None
    checks.append(
        _check_entry(
            "rule_set_entries_empty",
            label == "ok" and entries == [],
            {
                "httpStatus": status,
                "entryCount": len(entries) if entries is not None else None,
                "problems": problems,
            },
        )
    )

    label, status, bindings_data, problems = _signed_get_checked(
        gate, node, CARD_BINDINGS_TEMPLATE.format(card=settings.card_id), bindings_request_id
    )
    bindings = bindings_data if isinstance(bindings_data, list) else None
    already_bound = bool(
        bindings
        and any(
            isinstance(row, Mapping) and row.get("ruleSetId") == settings.rule_set_id
            for row in bindings
        )
    )
    # This GET requires require_platform_admin + require_card_context, so a 200
    # proves the ACTIVE global admin right AND the card context in one read --
    # legitimate mutation rights verified before any write.
    checks.append(
        _check_entry(
            "admin_active_and_card_context",
            label == "ok",
            {"httpStatus": status, "problems": problems},
        )
    )
    checks.append(
        _check_entry(
            "card_not_bound_to_rule_set",
            label == "ok" and not already_bound,
            {"bound": already_bound},
        )
    )

    try:
        all_binding_rows = gate.sql(
            "SELECT card_id FROM card_rule_set_ref WHERE rule_set_id=%d ORDER BY card_id"
            % settings.rule_set_id
        )
    except (AdapterError, OSError, ValueError) as error:
        all_binding_rows = []
        all_bindings_ok = False
        all_bindings_problem = type(error).__name__
    else:
        all_bindings_ok = len(all_binding_rows) == 0
        all_bindings_problem = None
    checks.append(
        _check_entry(
            "rule_set_not_bound_to_any_card",
            all_bindings_ok,
            {
                "boundCardCount": len(all_binding_rows) if all_bindings_problem is None else None,
                "errorClass": all_bindings_problem,
            },
        )
    )

    label, status, check_data, problems = _signed_get_checked(
        gate, node, check_path(settings), check_request_id
    )
    effect = str(check_data.get("effect")) if isinstance(check_data, Mapping) else None
    checks.append(
        _check_entry(
            "pre_grant_deny_check_endpoint",
            label == "ok" and effect in PRE_GRANT_SAFE_EFFECTS,
            {"httpStatus": status, "effect": effect, "problems": problems},
        )
    )

    try:
        stats_status, _body, _ = gate.signed_get(node, STATS_PATH, request_id=stats_request_id)
    except (AdapterError, OSError, ValueError) as error:
        checks.append(
            _check_entry("pre_grant_deny_stats", False, {"transportError": type(error).__name__})
        )
    else:
        checks.append(
            _check_entry(
                "pre_grant_deny_stats",
                stats_status is not None and stats_status != 200,
                {"httpStatus": stats_status},
            )
        )

    try:
        lines = gate.read_log_lines(node, [stats_request_id])
        smoke_events = parse_authz_events(lines, node)
    except (AdapterError, OSError, ValueError, EvidenceError) as error:
        checks.append(
            _check_entry(
                "e1_observability_smoke",
                False,
                {"reason": "log_slice_or_parse_failed", "errorClass": type(error).__name__},
            )
        )
    else:
        has_bound = any(event.event == "signed_context_bound" for event in smoke_events)
        checks.append(
            _check_entry(
                "e1_observability_smoke",
                bool(smoke_events) and has_bound,
                {"events": len(smoke_events)},
            )
        )

    # The durable reconciliation surface must be readable (SELECT-only); without
    # it no durable postcondition is ever provable, so the campaign is BLOCKED.
    baseline = []
    sql_ok = True
    for aggregate, aggregate_id in ((AGGREGATE_RULE_SET, settings.rule_set_id),):
        snapshot = projection_snapshot(gate, settings.tenant_id, aggregate, aggregate_id)
        baseline.append(snapshot)
        if snapshot.get("state") == "unknown":
            sql_ok = False
    checks.append(_check_entry("durable_reconciliation_surface", sql_ok, {"baseline": baseline}))

    failed = [check["check"] for check in checks if check["status"] != "PASS"]
    return {
        "node": node,
        "status": "PASS" if not failed else "BLOCKED",
        "checks": checks,
        "problems": failed,
    }


# ---------------------------------------------------------------------------
# Bounded reader race (same node as the cycle's mutation).
# ---------------------------------------------------------------------------


def _reader_loop(
    adapter: NodeAdapter,
    node: str,
    stop_event: threading.Event,
    attempts: List[Dict[str, Any]],
    launched: List[str],
    lock: threading.Lock,
    settings: E1Settings,
    cycle: int,
    reader_index: int,
) -> None:
    for sequence in range(settings.max_requests_per_reader):
        if stop_event.is_set():
            return
        request_id = reader_request_id(settings.run_id, cycle, reader_index, sequence)
        with lock:
            launched.append(request_id)
        try:
            http_status, _body, _ = adapter.signed_get(node, STATS_PATH, request_id=request_id)
        except (AdapterError, OSError, ValueError) as error:
            with lock:
                attempts.append(
                    {"requestId": request_id, "httpStatus": None, "error": type(error).__name__}
                )
            return
        with lock:
            attempts.append({"requestId": request_id, "httpStatus": int(http_status)})


def run_reader_race(
    adapter: NodeAdapter, node: str, settings: E1Settings, cycle: int
) -> Tuple[List[Dict[str, Any]], List[str], threading.Event, List[threading.Thread]]:
    """Start the bounded concurrent reader pool on one node."""
    stop_event = threading.Event()
    attempts: List[Dict[str, Any]] = []
    launched: List[str] = []
    lock = threading.Lock()
    threads: List[threading.Thread] = []

    def _wrapped(reader_index: int) -> None:
        _reader_loop(
            adapter,
            node,
            stop_event,
            attempts,
            launched,
            lock,
            settings,
            cycle,
            reader_index,
        )

    for reader_index in range(settings.readers):
        thread = threading.Thread(target=_wrapped, args=(reader_index,), daemon=True)
        thread.start()
        threads.append(thread)
    return attempts, launched, stop_event, threads


# ---------------------------------------------------------------------------
# Cleanup (finally semantics): reconcile first, correct at most once.
# ---------------------------------------------------------------------------


def _cleanup_after_cycle(
    adapter: NodeAdapter,
    settings: E1Settings,
    node: str,
    cycle_ops: Mapping[str, str],
    state: Mapping[str, Any],
    clock_ns: Optional[Callable[[], int]],
) -> Dict[str, Any]:
    """Finally-block cleanup for one cycle.

    Only known-safe corrective actions are taken; anything not provable is
    recorded as residual UNKNOWN and left for the human operator.
    """
    cleanup: Dict[str, Any] = {"corrective": [], "skipped": [], "residual": []}
    if state.get("readerThreadsActive") is True:
        cleanup["residual"].append("reader_threads_still_active_manual_reconciliation_required")
        cleanup["skipped"].extend(["deleteEntry:reader_threads_active", "unbind:reader_threads_active"])
        cleanup["manualReconciliationRequired"] = True
        return cleanup
    state_dict = state if isinstance(state, dict) else None
    entry_owned = state.get("entryOwnershipProven") is True
    entry_id = state.get("entryId") if entry_owned else None
    if not entry_owned and state.get("addAttempted") is True:
        # A committed add can outlive a lost response. Reconcile by this
        # cycle's operation id before deciding that there is nothing to clean.
        add_reconciled = reconcile_add_entry(adapter, settings.tenant_id, cycle_ops["addEntry"])
        if add_reconciled.get("state") == "applied":
            entry_id = int(add_reconciled["entryId"])
            entry_owned = True
            cleanup["skipped"].append("addEntry:reconciled_applied")
            if state_dict is not None:
                state_dict["entryId"] = entry_id
                state_dict["entryOwnershipProven"] = True
                state_dict["addReconciled"] = add_reconciled
        elif add_reconciled.get("state") == "unknown":
            cleanup["residual"].append("addEntry:reconciliation_unknown")
            if state_dict is not None:
                state_dict["addReconciled"] = add_reconciled
    elif state.get("addAttempted") is not True:
        cleanup["skipped"].append("deleteEntry:no_campaign_add_attempt")

    # The winning entry must be gone. The forward delete may have been the
    if entry_id is not None:
        delete_outcome = state.get("deleteOutcome")
        delete_reconciled = state.get("deleteReconciled")
        reconciled_state = (
            delete_reconciled.get("state") if isinstance(delete_reconciled, Mapping) else None
        )
        if reconciled_state == "applied":
            cleanup["skipped"].append("deleteEntry:already_applied")
        elif reconciled_state == "unknown":
            cleanup["residual"].append("deleteEntry:unknown_not_corrected")
        else:
            reconciled = reconcile_delete_entry(
                adapter,
                settings.tenant_id,
                settings.card_id,
                settings.rule_set_id,
                int(entry_id),
                cycle_ops["deleteEntry"],
                attempts=settings.reconcile_polls,
                interval_s=settings.reconcile_interval_s,
            )
            state_dict = state if isinstance(state, dict) else None
            if reconciled.get("state") == "applied":
                cleanup["skipped"].append("deleteEntry:already_applied")
                if state_dict is not None:
                    state_dict["deleteReconciled"] = reconciled
            elif reconciled.get("state") == "not_applied":
                attempt = issue_mutation(
                    adapter,
                    node,
                    "DELETE",
                    RULE_SET_ENTRY_TEMPLATE.format(
                        rule_set=settings.rule_set_id, entry=int(entry_id)
                    ),
                    None,
                    cycle_ops["deleteEntry"],
                    clock_ns=clock_ns,
                )
                cleanup["corrective"].append({"action": "deleteEntry", "attempt": attempt})
                if state_dict is not None:
                    state_dict["deleteOutcome"] = attempt["outcome"]
                if attempt["outcome"] == "committed":
                    after = reconcile_delete_entry(
                        adapter,
                        settings.tenant_id,
                        settings.card_id,
                        settings.rule_set_id,
                        int(entry_id),
                        cycle_ops["deleteEntry"],
                        attempts=settings.reconcile_polls,
                        interval_s=settings.reconcile_interval_s,
                    )
                    if state_dict is not None:
                        state_dict["deleteReconciled"] = after
                    if after.get("state") != "applied":
                        cleanup["residual"].append("deleteEntry:corrected_but_unproven")
                else:
                    cleanup["residual"].append("deleteEntry:corrective_%s" % attempt["outcome"])
            else:
                cleanup["residual"].append("deleteEntry:%s" % reconciled.get("state"))
                if state_dict is not None:
                    state_dict["deleteReconciled"] = reconciled
    else:
        cleanup["skipped"].append("deleteEntry:no_entry_id_recorded")

    # Only unbind a binding that this cycle actually attempted and durably
    # proved it owned. A preflight failure or an unproven bind must never delete
    # a binding created by another actor.
    bind_owned = state.get("bindOwnershipProven") is True
    bind_attempted = state.get("bindAttempted") is True
    if not bind_owned:
        bind_audit = fetch_audit_rows(adapter, settings.tenant_id, cycle_ops["bind"])
        if bind_audit is not None and any(
            row.get("changeType") == "BIND_CARD" for row in bind_audit
        ):
            bind_owned = True
            bind_attempted = True
            cleanup["skipped"].append("bind:reconciled_applied")
            if state_dict is not None:
                state_dict["bindAttempted"] = True
                state_dict["bindOwnershipProven"] = True
                state_dict["bindReconciled"] = {"state": "applied", "auditRows": bind_audit}
        elif bind_audit is None:
            cleanup["residual"].append("bind:reconciliation_unknown")
    if not bind_attempted or not bind_owned:
        cleanup["skipped"].append("unbind:not_campaign_owned")
        bound = bindings_contain(adapter, node, settings.card_id, settings.rule_set_id)
        if bound is True:
            cleanup["residual"].append("binding_not_campaign_owned")
    else:
        bound = bindings_contain(adapter, node, settings.card_id, settings.rule_set_id)
        if bound is True:
            attempt = issue_mutation(
                adapter,
                node,
                "DELETE",
                CARD_UNBIND_TEMPLATE.format(card=settings.card_id, rule_set=settings.rule_set_id),
                None,
                cycle_ops["unbind"],
                clock_ns=clock_ns,
            )
            cleanup["corrective"].append({"action": "unbind", "attempt": attempt})
            if attempt["outcome"] != "committed":
                cleanup["residual"].append("unbind:%s" % attempt["outcome"])
        elif bound is False:
            cleanup["skipped"].append("unbind:not_bound")
        else:
            cleanup["residual"].append("unbind:binding_state_unknown")

    # 3) Read-only final verification; failures are residual, never PASS.
    _label, _status, entries_data, _problems = _signed_get_checked(
        ReadOnlyGate(adapter),
        node,
        RULE_SET_ENTRIES_TEMPLATE.format(rule_set=settings.rule_set_id),
        stable_id(settings.run_id, "e1:cleanup:entries"),
    )
    bindings_after = bindings_contain(adapter, node, settings.card_id, settings.rule_set_id)
    cleanup["finalEntriesEmpty"] = entries_data == []
    cleanup["finalBound"] = bindings_after
    if entries_data != []:
        cleanup["residual"].append("entries_not_empty_after_cleanup")
    if bindings_after is not False:
        cleanup["residual"].append("binding_still_present_after_cleanup")
    return cleanup


# ---------------------------------------------------------------------------
# Cycle body.
# ---------------------------------------------------------------------------


def _cycle_status(counts: Mapping[str, int], problems: Sequence[str]) -> str:
    if counts.get("violations", 0) > 0:
        return "FAIL"
    if (
        counts.get("unclassified", 0) > 0
        or counts.get("unknown", 0) > 0
        or counts.get("durableUnknown", 0) > 0
        or problems
    ):
        return "UNKNOWN"
    return "PASS"


def _freeze_cycle(result: FrozenResult, out_dir: Path) -> FrozenResult:
    """Persist one cycle's evidence once and freeze it against rewrites."""
    result.freeze()
    atomic_json(out_dir / ("e1-cycle-%s.json" % result["cycle"]), result)
    return result


def _run_single_cycle(
    adapter: NodeAdapter,
    settings: E1Settings,
    cycle: int,
    node: str,
    out_dir: Path,
    clock_ns: Optional[Callable[[], int]],
    cleanup_state: Optional[Dict[str, Any]] = None,
) -> FrozenResult:
    cycle_ops = operation_ids_for_cycle(settings.run_id, cycle)
    owned_state = cleanup_state if cleanup_state is not None else {}
    owned_state.update(
        {
            "entryId": None,
            "addAttempted": False,
            "entryOwnershipProven": False,
            "bindAttempted": False,
            "bindOwnershipProven": False,
            "deleteAttempted": False,
        }
    )
    result = FrozenResult(
        {
            "cycle": cycle,
            "node": node,
            "operationIds": dict(cycle_ops),
            "entryId": None,
            "operations": {},
            "readerAttempts": [],
            "classifications": [],
            "mutationEvidence": None,
            "durable": {},
            "e0Grant": None,
            "counts": {
                "allow": 0,
                "deny": 0,
                "pending": 0,
                "unknown": 0,
                "unclassified": 0,
                "violations": 0,
                "durableUnknown": 0,
            },
            "cleanupState": owned_state,
            "problems": [],
            "status": "BLOCKED",
        }
    )
    problems: List[str] = result["problems"]
    out_dir.mkdir(parents=True, exist_ok=True)

    # Precondition re-assertion on this node: deny monitor before add/bind.
    pre = run_preflight_checks(ReadOnlyGate(adapter), settings, node)
    result["preconditions"] = {"status": pre["status"], "problems": pre["problems"]}
    if pre["status"] != "PASS":
        problems.append("preconditions_failed:%s" % ",".join(pre["problems"]))
        result["status"] = "BLOCKED"
        return _freeze_cycle(result, out_dir)

    # 1) Publish the candidate grant: add entry BEFORE bind.
    owned_state["addAttempted"] = True
    add_attempt = issue_mutation(
        adapter,
        node,
        "POST",
        RULE_SET_ENTRIES_TEMPLATE.format(rule_set=settings.rule_set_id),
        _entry_body(settings),
        cycle_ops["addEntry"],
        clock_ns=clock_ns,
    )
    result["operations"]["addEntry"] = add_attempt
    entry_id: Optional[int] = None
    if add_attempt["outcome"] == "committed":
        payload = _envelope_data(add_attempt.get("responseData"))
        raw_entry_id = payload.get("id") if payload else None
        if isinstance(raw_entry_id, int) and raw_entry_id > 0:
            entry_id = raw_entry_id
    if entry_id is None and add_attempt["outcome"] != "committed":
        reconciled_add = reconcile_add_entry(adapter, settings.tenant_id, cycle_ops["addEntry"])
        result["durable"]["addEntry"] = reconciled_add
        if reconciled_add.get("state") == "applied":
            entry_id = int(reconciled_add["entryId"])
        elif reconciled_add.get("state") == "unknown":
            result["counts"]["durableUnknown"] = 1
            problems.append("add_entry_outcome_unknown")
        else:
            problems.append("add_entry_not_applied")
    elif entry_id is None:
        problems.append("add_entry_response_missing_id")
    result["entryId"] = entry_id
    owned_state["entryId"] = entry_id
    owned_state["entryOwnershipProven"] = entry_id is not None and (
        add_attempt["outcome"] == "committed"
        or result["durable"].get("addEntry", {}).get("state") == "applied"
    )
    result["cleanupState"] = owned_state
    if entry_id is None:
        result["status"] = "UNKNOWN" if add_attempt["outcome"] != "rejected" else "BLOCKED"
        return _freeze_cycle(result, out_dir)

    # 2) Bind the rule set to the card (BASE).
    bind_attempt = issue_mutation(
        adapter,
        node,
        "POST",
        CARD_BIND_TEMPLATE.format(card=settings.card_id),
        _bind_body(settings),
        cycle_ops["bind"],
        clock_ns=clock_ns,
    )
    owned_state["bindAttempted"] = True
    result["operations"]["bind"] = bind_attempt
    bound = bindings_contain(adapter, node, settings.card_id, settings.rule_set_id)
    if bind_attempt["outcome"] == "committed" and bound is True:
        owned_state["bindOwnershipProven"] = True
        result["durable"]["bind"] = {"state": "applied", "bindingPresent": True}
    else:
        bind_state = (
            "not_applied"
            if bind_attempt["outcome"] == "rejected" and bound is False
            else "unknown"
        )
        result["durable"]["bind"] = {
            "state": bind_state,
            "bindingPresent": bound,
            "bindHttpOutcome": bind_attempt["outcome"],
        }
        if bind_state == "unknown":
            result["counts"]["durableUnknown"] = 1
            problems.append("bind_outcome_unknown")
        else:
            problems.append("bind_not_proven_applied")
        result["status"] = "UNKNOWN" if bind_state == "unknown" else "BLOCKED"
        return _freeze_cycle(result, out_dir)

    # 3) Durable wait: this RuleSet flow publishes only the RULE_SET delta
    # chain. The pointer remains card-scoped through its stored card_id; a
    # USER_CARD delta would instead belong to a direct permission-rule mutation.
    quiescent, snapshots = wait_projection_quiescent(
        adapter,
        settings.tenant_id,
        [(AGGREGATE_RULE_SET, settings.rule_set_id)],
        attempts=settings.reconcile_polls,
        interval_s=settings.reconcile_interval_s,
    )
    result["durable"]["bindPublication"] = {"quiescent": quiescent, "snapshots": snapshots}
    if not quiescent:
        problems.append("bind_projection_not_quiescent")
        result["counts"]["durableUnknown"] = 1
        result["status"] = "UNKNOWN"
        return _freeze_cycle(result, out_dir)

    # 4) E0 grant evidence on the same node: ALLOW via check + admitted stats.
    e0_check_request_id = stable_id(settings.run_id, "e1:c%d:e0:check" % cycle)
    check_label, check_status, check_data, _ignored = _signed_get_checked(
        ReadOnlyGate(adapter), node, check_path(settings), e0_check_request_id
    )
    effect = str(check_data.get("effect")) if isinstance(check_data, Mapping) else None
    reason = str(check_data.get("reason")) if isinstance(check_data, Mapping) else None
    e0_status: Optional[int]
    e0_request_id = stable_id(settings.run_id, "e1:c%d:e0:stats" % cycle)
    try:
        e0_status, _body, _ = adapter.signed_get(
            node, STATS_PATH, request_id=e0_request_id
        )
    except (AdapterError, OSError, ValueError) as error:
        e0_status = None
        problems.append("e0_stats_transport:%s" % type(error).__name__)
    e0_identity: Optional[Tuple[Any, ...]] = None
    if check_status == 200 and effect == CHECK_EFFECT_ALLOW and e0_status == 200:
        try:
            e0_lines = adapter.read_log_lines(node, [e0_request_id])
            e0_events = events_for_request(parse_authz_events(e0_lines, node), e0_request_id)
            e0_identity = _event_candidate_identity(
                experiment_common.one_event(e0_events, "candidate_match")
            )
            if e0_identity[0] != settings.tenant_id or e0_identity[1] != settings.card_id:
                problems.append("e0_candidate_scope_mismatch")
                e0_identity = None
        except (AdapterError, OSError, ValueError, EvidenceError) as error:
            problems.append("e0_identity_unproven:%s" % type(error).__name__)
    result["e0Grant"] = {
        "checkHttp": check_status,
        "checkLabel": check_label,
        "effect": effect,
        "reason": reason,
        "statsHttp": e0_status,
        "candidateIdentity": list(e0_identity) if e0_identity is not None else None,
    }
    if check_status != 200 or effect != CHECK_EFFECT_ALLOW or e0_status != 200 or e0_identity is None:
        problems.append("e0_grant_not_proven_allow")
        result["status"] = "BLOCKED"
        return _freeze_cycle(result, out_dir)

    # 5) Bounded concurrent reader race on the same node.
    attempts, launched_reader_ids, stop_event, threads = run_reader_race(
        adapter, node, settings, cycle
    )
    owned_state["readerThreadsActive"] = True

    # 6) The source mutation under test: DELETE the winning entry.
    delete_attempt = issue_mutation(
        adapter,
        node,
        "DELETE",
        RULE_SET_ENTRY_TEMPLATE.format(rule_set=settings.rule_set_id, entry=int(entry_id)),
        None,
        cycle_ops["deleteEntry"],
        clock_ns=clock_ns,
    )
    result["operations"]["deleteEntry"] = delete_attempt
    state_for_cleanup: Dict[str, Any] = owned_state
    state_for_cleanup["deleteAttempted"] = True
    state_for_cleanup["deleteOutcome"] = delete_attempt["outcome"]
    reconciled_delete: Optional[Dict[str, Any]] = None
    if delete_attempt["outcome"] in ("committed", "rejected", "unknown"):
        reconciled_delete = reconcile_delete_entry(
            adapter,
            settings.tenant_id,
            settings.card_id,
            settings.rule_set_id,
            int(entry_id),
            cycle_ops["deleteEntry"],
            attempts=settings.reconcile_polls,
            interval_s=settings.reconcile_interval_s,
        )
        result["durable"]["deleteEntry"] = reconciled_delete
        state_for_cleanup["deleteReconciled"] = reconciled_delete
        if delete_attempt["outcome"] == "committed":
            if reconciled_delete.get("state") != "applied":
                result["counts"]["durableUnknown"] = 1
                problems.append("delete_durable_postcondition_unproven")
        elif delete_attempt["outcome"] == "unknown":
            if reconciled_delete.get("state") == "not_applied":
                # Single corrective attempt is deferred to the finally-cleanup,
                # which reconciles again before acting. The forward attempt is
                # still recorded as unresolved for this cycle (never folded
                # into PASS).
                problems.append("delete_forward_unknown_corrective_deferred")
            elif reconciled_delete.get("state") == "applied":
                problems.append("delete_unknown_but_reconciled_applied")
            else:
                result["counts"]["durableUnknown"] = 1
                problems.append("delete_outcome_unknown")
        else:  # rejected
            if reconciled_delete.get("state") != "applied":
                problems.append("delete_rejected_and_not_applied")
    result["cleanupState"] = state_for_cleanup

    # 7) Stop readers and require complete terminal evidence before classifying.
    stop_event.set()
    for thread in threads:
        thread.join(timeout=READER_JOIN_TIMEOUT_S)
    active_threads = [thread for thread in threads if thread.is_alive()]
    result["readerThreadsActive"] = bool(active_threads)
    owned_state["readerThreadsActive"] = bool(active_threads)
    result["readerAttempts"] = list(attempts)
    result["readerRequestsLaunched"] = list(launched_reader_ids)
    terminal_ids = {
        str(attempt.get("requestId")) for attempt in attempts if attempt.get("requestId")
    }
    missing_terminal_ids = sorted(set(launched_reader_ids) - terminal_ids)
    if active_threads or missing_terminal_ids:
        result["counts"]["unknown"] += max(len(active_threads), len(missing_terminal_ids), 1)
        problems.append("reader_requests_without_terminal_evidence")

    reader_ids = [
        str(attempt.get("requestId")) for attempt in attempts if attempt.get("requestId")
    ]
    identifiers = reader_ids + [cycle_ops["deleteEntry"]]
    events: List[experiment_common.Event] = []
    try:
        lines = adapter.read_log_lines(node, identifiers)
        events = parse_authz_events(lines, node)
    except (AdapterError, OSError, ValueError, EvidenceError) as error:
        problems.append("log_slice_failed:%s" % type(error).__name__)
        result["counts"]["unknown"] = len(reader_ids)
        result["counts"]["unclassified"] = sum(
            1 for attempt in attempts if attempt.get("httpStatus") == 200
        )
    else:
        if not events:
            problems.append("log_slice_returned_no_e1_events")
            result["counts"]["unknown"] = max(len(reader_ids), 1)
            result["counts"]["unclassified"] = sum(
                1 for attempt in attempts if attempt.get("httpStatus") == 200
            )
        else:
            classifications, mutation_evidence = classify_reader_requests(
                events, attempts, cycle_ops["deleteEntry"], e0_identity
            )
            result["classifications"] = classifications
            result["mutationEvidence"] = mutation_evidence
            counts = result["counts"]
            for row in classifications:
                if row.get("staleAllowViolation"):
                    counts["violations"] += 1
                if row.get("category") == "unclassified-unknown":
                    counts["unclassified"] += 1
                decision = row.get("decision")
                if decision == "UNKNOWN" or row.get("problems"):
                    counts["unknown"] += 1
                elif decision == "ALLOW":
                    counts["allow"] += 1
                elif decision == "DENY":
                    counts["deny"] += 1
                elif decision == "PENDING":
                    counts["pending"] += 1
                else:
                    counts["unknown"] += 1

    result["status"] = _cycle_status(result["counts"], problems)
    return _freeze_cycle(result, out_dir)


def _envelope_data(response: Any) -> Optional[Mapping[str, Any]]:
    data = response.get("data") if isinstance(response, Mapping) else None
    return data if isinstance(data, Mapping) else None


def _run_cycle_with_cleanup(
    adapter: NodeAdapter,
    settings: E1Settings,
    cycle: int,
    node: str,
    out_dir: Path,
    clock_ns: Optional[Callable[[], int]],
) -> Tuple[FrozenResult, Dict[str, Any]]:
    """Run one cycle and convert unexpected cycle errors to UNKNOWN evidence."""
    cycle_state: Dict[str, Any] = {}
    result: Optional[FrozenResult] = None
    cycle_error: Optional[Exception] = None
    cleanup: Dict[str, Any] = {
        "corrective": [],
        "skipped": [],
        "residual": ["cycle_failed_before_evidence"],
    }
    try:
        result = _run_single_cycle(adapter, settings, cycle, node, out_dir, clock_ns, cycle_state)
    except Exception as error:
        cycle_error = error
        result = FrozenResult(
            {
                "cycle": cycle,
                "node": node,
                "operationIds": operation_ids_for_cycle(settings.run_id, cycle),
                "entryId": cycle_state.get("entryId"),
                "operations": {},
                "readerAttempts": [],
                "classifications": [],
                "mutationEvidence": None,
                "durable": {},
                "e0Grant": None,
                "counts": {
                    "allow": 0,
                    "deny": 0,
                    "pending": 0,
                    "unknown": 1,
                    "unclassified": 0,
                    "violations": 0,
                    "durableUnknown": 1,
                },
                "cleanupState": cycle_state,
                "problems": ["cycle_exception:%s" % type(error).__name__],
                "status": "UNKNOWN",
            }
        )
    finally:
        try:
            state = result.get("cleanupState") if result is not None else cycle_state
            state_map = dict(state) if isinstance(state, Mapping) else dict(cycle_state)
            if result is not None and "entryId" not in state_map:
                state_map["entryId"] = result.get("entryId")
            cycle_ops = operation_ids_for_cycle(settings.run_id, cycle)
            cleanup = _cleanup_after_cycle(adapter, settings, node, cycle_ops, state_map, clock_ns)
        except Exception as error:
            cleanup["residual"].append("cleanup_failed:%s" % type(error).__name__)
        try:
            atomic_json(
                out_dir / ("e1-cycle-%s-cleanup.json" % cycle),
                {"cycle": cycle, "node": node, "cleanup": cleanup},
            )
        except Exception:
            cleanup["residual"].append("cleanup_evidence_write_failed")

    assert result is not None
    if cycle_error is not None:
        cycle_path = out_dir / ("e1-cycle-%s.json" % cycle)
        if not cycle_path.exists():
            _freeze_cycle(result, out_dir)
    return result, cleanup


# ---------------------------------------------------------------------------
# Live gate (Exec-L3; approval is explicit and never inferred from config).
# ---------------------------------------------------------------------------


APPROVAL_SCOPE = "E1-LIVE-CAMPAIGN"


def _check_live_gate(
    live: bool,
    approval_ref: Optional[str],
    approval_record: Optional[str],
    confirm_exec_l3: bool,
    settings: E1Settings,
) -> Optional[str]:
    """Return a block reason when the live gate is not fully satisfied.

    The gate is mechanical only: it validates explicitly caller-supplied
    artifacts (CLI flags plus an external approval record) and never reads any
    approval from the run config. Passing it does not constitute the AGENTS.md
    Exec-L3 user approval, which must be obtained separately for the specific
    run by a human.
    """
    if not live:
        return "live_not_enabled"
    if not confirm_exec_l3:
        return "exec_l3_human_confirmation_missing"
    if not isinstance(approval_ref, str) or not _APPROVAL_REF_RE.fullmatch(approval_ref):
        return "approval_ref_missing_or_unsafe"
    if not isinstance(approval_record, str) or not approval_record:
        return "approval_record_missing"
    try:
        record = json.loads(Path(approval_record).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return "approval_record_unreadable:%s" % type(error).__name__
    if not isinstance(record, Mapping):
        return "approval_record_not_a_mapping"
    if record.get("run_id") != settings.run_id:
        return "approval_record_run_id_mismatch"
    if record.get("approval_ref") != approval_ref:
        return "approval_record_ref_mismatch"
    if record.get("approval_scope") != APPROVAL_SCOPE:
        return "approval_record_scope_mismatch"
    approved_by = record.get("approved_by")
    if not isinstance(approved_by, str) or not approved_by.strip():
        return "approval_record_approver_missing"
    approved_at = record.get("approved_at")
    if not isinstance(approved_at, str) or not _ISO_DATETIME_RE.fullmatch(approved_at):
        return "approval_record_timestamp_missing"
    return None


def _build_adapter(raw_config: Mapping[str, Any]) -> NodeAdapter:
    """Production adapter construction (inert until a method is called)."""
    adapter_config, _settings = load_e1_config(raw_config)
    actor = Actor.from_mapping(raw_config["e1"]["admin_actor"])
    return NodeAdapter(adapter_config, actor=actor)


def _config_sha256(raw_config: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(raw_config, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Entry points: plan (offline), preflight (read-only remote), campaign (live).
# ---------------------------------------------------------------------------


def execute_plan(raw_config: Mapping[str, Any], out_dir: Path) -> Dict[str, Any]:
    """Offline planning: no adapter is ever constructed; no node is contacted."""
    _adapter_config, settings = load_e1_config(raw_config)
    out_dir = Path(out_dir)
    cycles: List[Dict[str, Any]] = []
    for cycle in range(1, settings.cycles + 1):
        cycles.append(
            {
                "cycle": cycle,
                "node": settings.node_rotation[(cycle - 1) % len(settings.node_rotation)],
                "operationIds": operation_ids_for_cycle(settings.run_id, cycle),
                "readerRequestLabelPattern": "e1:c{cycle}:r{reader}:n{seq}",
                "readerRequestBudget": settings.readers * settings.max_requests_per_reader,
            }
        )
    plan = {
        "campaignId": settings.run_id,
        "experiment": "E1",
        "mode": "plan",
        "status": "PLANNED",
        "settings": settings.public_metadata(),
        "provenance": public_provenance(raw_config),
        "configSha256": _config_sha256(raw_config),
        "operationOrder": list(OP_ORDER),
        "cycles": cycles,
        "bounds": {
            "maxCycles": MAX_CYCLES,
            "maxReaders": MAX_READERS,
            "maxRequestsPerReader": MAX_REQUESTS_PER_READER,
            "maxReconcilePolls": MAX_RECONCILE_POLLS,
        },
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    atomic_json(out_dir / "plan.json", plan)
    write_checksums(out_dir, [out_dir / "plan.json"])
    return plan


def execute_preflight(
    raw_config: Mapping[str, Any],
    out_dir: Path,
    *,
    gate_factory: Optional[Callable[[], Any]] = None,
) -> Dict[str, Any]:
    """Explicit remote read-only preflight (GET + SELECT only)."""
    _adapter_config, settings = load_e1_config(raw_config)
    out_dir = Path(out_dir)
    report: Dict[str, Any] = {
        "campaignId": settings.run_id,
        "experiment": "E1",
        "mode": "preflight",
        "settings": settings.public_metadata(),
        "provenance": public_provenance(raw_config),
        "configSha256": _config_sha256(raw_config),
    }
    factory = gate_factory if gate_factory is not None else (lambda: ReadOnlyGate(_build_adapter(raw_config)))
    gate = factory()
    preflight = run_preflight_checks(gate, settings, settings.node_rotation[0])
    report["preflight"] = preflight
    report["status"] = preflight["status"]
    out_dir.mkdir(parents=True, exist_ok=True)
    atomic_json(out_dir / "preflight.json", report)
    write_checksums(out_dir, [out_dir / "preflight.json"])
    return report


def execute_campaign(
    raw_config: Mapping[str, Any],
    out_dir: Path,
    *,
    live: bool,
    approval_ref: Optional[str],
    approval_record: Optional[str],
    confirm_exec_l3: bool = False,
    approval_validator: Optional[Callable[[str, str, str], bool]] = None,
    adapter_factory: Optional[Callable[[], NodeAdapter]] = None,
    clock_ns: Optional[Callable[[], int]] = None,
) -> Dict[str, Any]:
    """Full E1 campaign. Live mutations require the explicit multi-factor gate.

    Passing the gate is mechanical only; the AGENTS.md Exec-L3 human approval
    for the specific run must additionally exist before any live execution.
    """
    _adapter_config, settings = load_e1_config(raw_config)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {
        "campaignId": settings.run_id,
        "experiment": "E1",
        "mode": "campaign",
        "status": "BLOCKED",
        "settings": settings.public_metadata(),
        "provenance": public_provenance(raw_config),
        "configSha256": _config_sha256(raw_config),
        "apiContract": {
            "statsPath": STATS_PATH,
            "checkPathTemplate": CHECK_PATH_TEMPLATE,
            "aggregates": [AGGREGATE_RULE_SET],
        },
        "approvalRef": approval_ref if live else None,
        "approvalGate": {
            "liveFlag": bool(live),
            "confirmExecL3": bool(confirm_exec_l3),
            "externalRecordRequired": True,
            "independentApprovalValidatorRequired": True,
            "note": "mechanical artifacts are necessary but never sufficient; the embedding caller must independently verify AGENTS.md Exec-L3 approval for this exact run and config hash",
        },
        "cycles": [],
        "problems": [],
    }

    gate_problem = _check_live_gate(
        live, approval_ref, approval_record, confirm_exec_l3, settings
    )
    if gate_problem is not None:
        manifest["problems"].append(gate_problem)
        atomic_json(out_dir / "manifest.json", manifest)
        write_checksums(out_dir, [out_dir / "manifest.json"])
        return manifest
    if approval_validator is None:
        manifest["problems"].append("independent_user_approval_not_verified")
        atomic_json(out_dir / "manifest.json", manifest)
        write_checksums(out_dir, [out_dir / "manifest.json"])
        return manifest
    try:
        approval_verified = approval_validator(settings.run_id, str(approval_ref), _config_sha256(raw_config))
    except Exception:
        approval_verified = False
    if approval_verified is not True:
        manifest["problems"].append("independent_user_approval_not_verified")
        atomic_json(out_dir / "manifest.json", manifest)
        write_checksums(out_dir, [out_dir / "manifest.json"])
        return manifest

    factory = adapter_factory if adapter_factory is not None else (
        lambda: _build_adapter(raw_config)
    )
    adapter = factory()

    preflight = run_preflight_checks(ReadOnlyGate(adapter), settings, settings.node_rotation[0])
    manifest["preflight"] = {"status": preflight["status"], "problems": preflight["problems"]}
    atomic_json(out_dir / "preflight.json", preflight)
    if preflight["status"] != "PASS":
        manifest["problems"].append("preflight_blocked")
        atomic_json(out_dir / "manifest.json", manifest)
        artifacts = [out_dir / "manifest.json", out_dir / "preflight.json"]
        write_checksums(out_dir, artifacts)
        return manifest

    statuses: List[str] = []
    try:
        for cycle in range(1, settings.cycles + 1):
            node = settings.node_rotation[(cycle - 1) % len(settings.node_rotation)]
            result, cleanup = _run_cycle_with_cleanup(
                adapter, settings, cycle, node, out_dir, clock_ns
            )
            statuses.append(str(result["status"]))
            cycle_summary = {
                "cycle": result["cycle"],
                "node": result["node"],
                "status": result["status"],
                "counts": dict(result["counts"]),
                "operationIds": dict(result["operationIds"]),
                "cleanupResidual": list(cleanup.get("residual", [])),
            }
            if cleanup.get("residual"):
                statuses.append("UNKNOWN")
            manifest["cycles"].append(cycle_summary)
            manifest["problems"].extend(
                "cycle_%d:%s" % (cycle, problem) for problem in cleanup.get("residual", [])
            )
    finally:
        # The per-cycle finally-cleanup has already reconciled and recorded its
        # residuals; nothing is retried here.
        pass

    manifest["status"] = worst_status(statuses) if statuses else "BLOCKED"
    atomic_json(out_dir / "manifest.json", manifest)
    artifacts = [out_dir / "manifest.json", out_dir / "preflight.json"]
    artifacts.extend(sorted(out_dir.glob("e1-cycle-*.json")))
    write_checksums(out_dir, artifacts)
    return manifest


# ---------------------------------------------------------------------------
# CLI. Default mode 'plan' is offline and never contacts nodes.
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="e1_runner.py",
        description=(
            "E1 campaign runner. Default mode 'plan' is offline and never "
            "contacts nodes. 'preflight' is read-only remote (GET + SELECT "
            "only). The standalone 'run --live' CLI remains BLOCKED because "
            "only an embedding caller can supply the independent approval validator "
            "required before Exec-L3 mutations."
        ),
    )
    parser.add_argument("mode", nargs="?", choices=("plan", "preflight", "run"), default="plan")
    parser.add_argument("--config", required=True, help="path to the run config JSON")
    parser.add_argument("--out", default="e1_out", help="evidence output directory")
    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "request live mode; standalone CLI remains BLOCKED without an embedding "
            "independent approval validator"
        ),
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
    parser.add_argument(
        "--confirm-exec-l3",
        action="store_true",
        help=(
            "explicit human confirmation that the AGENTS.md Exec-L3 approval "
            "for THIS run exists (required with --live; mechanical only)"
        ),
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
        elif args.mode == "preflight":
            result = execute_preflight(raw_config, out_dir)
        elif not args.live:
            # 'run' without --live stays fully offline by design: no adapter is
            # constructed and no node is contacted.
            _adapter_config, settings = load_e1_config(raw_config)
            result = {
                "campaignId": settings.run_id,
                "experiment": "E1",
                "mode": "run",
                "status": "BLOCKED",
                "problems": ["live_not_enabled"],
                "settings": settings.public_metadata(),
                "configSha256": _config_sha256(raw_config),
            }
            out_dir.mkdir(parents=True, exist_ok=True)
            atomic_json(out_dir / "manifest.json", result)
            write_checksums(out_dir, [out_dir / "manifest.json"])
        else:
            result = execute_campaign(
                raw_config,
                out_dir,
                live=True,
                approval_ref=args.approval_ref,
                approval_record=args.approval_record,
                confirm_exec_l3=args.confirm_exec_l3,
            )
    except (ConfigError, E1Error) as error:
        print("blocked:%s" % error, file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "mode": result.get("mode"),
                "campaignId": result.get("campaignId"),
                "status": result.get("status"),
            },
            sort_keys=True,
        )
    )
    return 0 if result.get("status") in {"PASS", "PLANNED"} else 1


if __name__ == "__main__":
    sys.exit(main())
