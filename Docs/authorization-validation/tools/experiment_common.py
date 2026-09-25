#!/usr/bin/env python3
"""Shared, side-effect-free helpers for authorization validation runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

ALLOWED_STATUSES = {"PASS", "FAIL", "BLOCKED", "UNKNOWN", "PENDING", "SKIP", "PLANNED"}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(RuntimeError):
    """Evidence is malformed or insufficient for a verdict."""


@dataclass(frozen=True)
class Event:
    event: str
    request_id: str
    sequence: int
    wall_unix_ns: int
    fields: Mapping[str, Any]
    node: str = ""
    # Random identifier, stable for one process lifetime. `sequence` is only
    # comparable inside the same (node, process_observation_id) epoch; a parser
    # or classifier that sees more than one epoch must refuse the evidence.
    process_observation_id: str = ""


@dataclass(frozen=True)
class E3Event:
    event: str
    process_observation_id: str
    sequence: int
    wall_unix_ns: int
    delta_event_id: int
    event_id: str
    operation_id: Optional[str]
    attempts: Optional[int]
    fields: Mapping[str, Any]
    node: str = ""


@dataclass(frozen=True)
class E4Event:
    event: str
    process_observation_id: str
    sequence: int
    wall_unix_ns: int
    fields: Mapping[str, Any]
    node: str = ""


E3_TERMINAL_EVENTS = frozenset(
    {
        "publish_committed",
        "quarantine_committed",
        "terminal_unknown",
        "lease_left_to_expire",
        "backoff_committed",
        "release_committed",
    }
)
E3_NONTERMINAL_EVENTS = frozenset({"retry_scheduled", "pointer_replan", "release_requested"})


@dataclass(frozen=True)
class SequenceInterval:
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start <= 0 or self.end < self.start:
            raise EvidenceError(f"invalid event interval [{self.start}, {self.end}]")

    def before(self, other: "SequenceInterval") -> bool:
        return self.end < other.start

    def overlaps(self, other: "SequenceInterval") -> bool:
        return not (self.before(other) or other.before(self))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_id(run_id: str, label: str) -> str:
    if not SAFE_ID.fullmatch(run_id) or not SAFE_ID.fullmatch(label):
        raise EvidenceError("run_id and label must use the safe identifier alphabet")
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{run_id}:authorization-validation:{label}"))


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_checksums(root: Path, paths: Iterable[Path]) -> Path:
    targets = sorted({path.resolve() for path in paths})
    lines = []
    for path in targets:
        relative = path.relative_to(root.resolve()).as_posix()
        lines.append(f"{sha256_file(path)}  {relative}")
    destination = root / "checksums.sha256"
    destination.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    verify_checksums(root, destination)
    return destination


def verify_checksums(root: Path, checksum_file: Path) -> None:
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        expected, separator, relative = line.partition("  ")
        if separator != "  " or not SHA256.fullmatch(expected):
            raise EvidenceError(f"malformed checksum line: {line!r}")
        target = (root / relative).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError as error:
            raise EvidenceError(f"checksum path escapes artifact root: {relative}") from error
        actual = sha256_file(target)
        if actual != expected:
            raise EvidenceError(f"checksum mismatch for {relative}")


def validate_run_config_shape(config: Mapping[str, Any]) -> list[str]:
    required = {
        "run_id",
        "nodes",
        "ssh",
        "base_dir",
        "db",
        "mysql_container",
        "redis_container",
        "hmac_secret_file",
        "binary_sha256",
        "source_snapshot_sha256",
        "source_git_rev",
        "source_dirty_patch_sha256",
        "bootstrap_bin_sha256",
    }
    problems = [f"missing:{name}" for name in sorted(required - set(config))]
    run_id = config.get("run_id")
    if not isinstance(run_id, str) or not SAFE_ID.fullmatch(run_id):
        problems.append("invalid:run_id")
    nodes = config.get("nodes")
    if not isinstance(nodes, dict) or set(nodes) != {"node-a", "node-b", "node-c"}:
        problems.append("invalid:nodes")
    for field in (
        "binary_sha256",
        "source_snapshot_sha256",
        "source_dirty_patch_sha256",
        "bootstrap_bin_sha256",
    ):
        value = config.get(field)
        if not isinstance(value, str) or not SHA256.fullmatch(value.lower()):
            problems.append(f"invalid:{field}")
    source_rev = config.get("source_git_rev")
    if not isinstance(source_rev, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", source_rev):
        problems.append("invalid:source_git_rev")
    return sorted(set(problems))


def public_provenance(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "runId": config.get("run_id"),
        "binarySha256": config.get("binary_sha256"),
        "sourceSnapshotSha256": config.get("source_snapshot_sha256"),
        "sourceGitRev": config.get("source_git_rev"),
        "sourceDirty": config.get("source_dirty"),
        "sourceDirtyPatchSha256": config.get("source_dirty_patch_sha256"),
        "bootstrapBinSha256": config.get("bootstrap_bin_sha256"),
        "nodeLabels": sorted((config.get("nodes") or {}).keys()),
    }


def _flatten_trace_record(record: Mapping[str, Any]) -> dict[str, Any]:
    fields = record.get("fields")
    flattened: dict[str, Any] = {}
    if isinstance(fields, Mapping):
        flattened.update(fields)
    for key, value in record.items():
        if key != "fields" and key not in flattened:
            flattened[key] = value
    return flattened


def parse_authz_events(lines: Iterable[str], node: str = "") -> list[Event]:
    events: list[Event] = []
    for line_number, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, Mapping):
            continue
        flattened = _flatten_trace_record(record)
        if flattened.get("message") != "e1 authorization observation":
            continue
        event = flattened.get("event")
        request_id = flattened.get("request_id")
        process_id = flattened.get("process_observation_id")
        try:
            sequence = int(flattened.get("event_sequence"))
            wall_unix_ns = int(flattened.get("wall_unix_ns"))
        except (TypeError, ValueError) as error:
            raise EvidenceError(f"invalid authz event number at line {line_number}") from error
        if not isinstance(event, str) or not event:
            raise EvidenceError(f"missing authz event name at line {line_number}")
        if not isinstance(request_id, str) or not request_id:
            raise EvidenceError(f"missing request_id at line {line_number}")
        if not isinstance(process_id, str) or not SAFE_ID.fullmatch(process_id.replace("-", "_")):
            raise EvidenceError(f"missing or unsafe E1 process observation id at line {line_number}")
        events.append(Event(event, request_id, sequence, wall_unix_ns, flattened, node, process_id))
    # Event sequences are process-local: keep epochs contiguous and scope
    # duplicate detection to one (node, process epoch). The same sequence value
    # in two epochs of one node is legal (a restart restarts the counter).
    events.sort(key=lambda item: (item.node, item.process_observation_id, item.sequence))
    seen: set[tuple[str, str, int]] = set()
    for event in events:
        key = (event.node, event.process_observation_id, event.sequence)
        if key in seen:
            raise EvidenceError(
                f"duplicate event_sequence {event.sequence} in {event.process_observation_id} "
                f"on {event.node or 'node'}"
            )
        seen.add(key)
    return events


def parse_e4_events(lines: Iterable[str], node: str = "") -> list[E4Event]:
    events: list[E4Event] = []
    for line_number, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, Mapping):
            continue
        flattened = _flatten_trace_record(record)
        if flattened.get("message") != "e4 deployment precondition observation":
            continue
        event = flattened.get("event")
        process_id = flattened.get("process_observation_id")
        try:
            sequence = int(flattened.get("event_sequence"))
            wall_unix_ns = int(flattened.get("wall_unix_ns"))
        except (TypeError, ValueError) as error:
            raise EvidenceError(f"invalid E4 event number at line {line_number}") from error
        if event not in {"pool_connection_precondition", "cache_epoch_observed"}:
            raise EvidenceError(f"invalid E4 event at line {line_number}")
        if not isinstance(process_id, str) or not process_id:
            raise EvidenceError(f"missing E4 process observation id at line {line_number}")
        events.append(E4Event(str(event), process_id, sequence, wall_unix_ns, flattened, node))
    seen: set[tuple[str, str, int]] = set()
    for event in events:
        key = (event.node, event.process_observation_id, event.sequence)
        if event.sequence <= 0 or key in seen:
            raise EvidenceError("invalid or duplicate E4 process event sequence")
        seen.add(key)
    events.sort(key=lambda item: (item.node, item.process_observation_id, item.sequence))
    return events


def validate_e4_runtime_preconditions(
    events: Sequence[E4Event],
    expected_nodes: Sequence[str],
    *,
    clock_skew_threshold_ns: int = 2_000_000_000,
    rotation_journal_present: bool = False,
    expected_pool_connections: Optional[Mapping[str, int]] = None,
) -> dict[str, Any]:
    if clock_skew_threshold_ns < 0:
        raise EvidenceError("clock skew threshold must be non-negative")
    if not expected_nodes or any(not node for node in expected_nodes):
        raise EvidenceError("expected_nodes must be non-empty labels")
    if expected_pool_connections is not None and any(
        node not in expected_pool_connections
        or not isinstance(expected_pool_connections[node], int)
        or isinstance(expected_pool_connections[node], bool)
        or expected_pool_connections[node] <= 0
        for node in expected_nodes
    ):
        raise EvidenceError("expected_pool_connections requires a positive count per node")
    connections = [event for event in events if event.event == "pool_connection_precondition"]
    epochs = [event for event in events if event.event == "cache_epoch_observed"]
    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    blocked: list[str] = []
    unknown: list[str] = []
    for node in expected_nodes:
        node_connections = [event for event in connections if event.node == node]
        if not node_connections:
            blocked.append(f"{node}:no_pool_connection_observation")
            continue
        identities: dict[tuple[str, int], tuple[Any, ...]] = {}
        valid_connection_keys: set[tuple[str, int]] = set()
        for event in node_connections:
            fields = event.fields
            try:
                connection_id = int(fields.get("connection_id"))
                lower = int(fields.get("offset_lower_ns"))
                upper = int(fields.get("offset_upper_ns"))
                wall_start = int(fields.get("wall_start_ns"))
                wall_end = int(fields.get("wall_end_ns"))
                db_utc = int(fields.get("db_utc_unix_ns"))
            except (TypeError, ValueError):
                unknown.append(f"{node}:malformed_pool_connection_observation")
                continue
            if (
                connection_id <= 0
                or wall_start <= 0
                or wall_end < wall_start
                or db_utc <= 0
                or lower != db_utc - wall_end
                or upper != db_utc - wall_start
            ):
                unknown.append(f"{node}:{connection_id}:invalid_clock_interval_evidence")
                continue
            if fields.get("db_clock_inside_call_interval") is not (
                wall_start <= db_utc <= wall_end
            ):
                unknown.append(f"{node}:{connection_id}:clock_interval_flag_mismatch")
                continue
            server_hash = fields.get("server_identity_sha256")
            isolation = str(fields.get("session_isolation") or "").upper().replace("_", "-")
            time_zone = str(fields.get("session_time_zone") or "")
            primary = fields.get("primary_route") is True
            if not isinstance(server_hash, str) or not SHA256.fullmatch(server_hash):
                unknown.append(f"{node}:{connection_id}:invalid_server_hash")
                continue
            if isolation not in {
                "READ-UNCOMMITTED",
                "READ-COMMITTED",
                "REPEATABLE-READ",
                "SERIALIZABLE",
            }:
                failures.append(f"{node}:{connection_id}:unsupported_isolation")
            if time_zone not in {"+00:00", "UTC"}:
                failures.append(f"{node}:{connection_id}:session_not_utc")
            if not primary:
                failures.append(f"{node}:{connection_id}:not_primary")
            if lower > upper:
                unknown.append(f"{node}:{connection_id}:invalid_clock_interval")
            elif lower > clock_skew_threshold_ns or upper < -clock_skew_threshold_ns:
                failures.append(f"{node}:{connection_id}:clock_offset_out_of_bounds")
            identity_key = (event.process_observation_id, connection_id)
            identity_value = (server_hash, isolation, time_zone, primary)
            prior = identities.get(identity_key)
            if prior is not None and prior != identity_value:
                failures.append(f"{node}:{connection_id}:connection_precondition_drift")
            identities[identity_key] = identity_value
            valid_connection_keys.add(identity_key)
            checks.append(
                {
                    "node": node,
                    "processObservationId": event.process_observation_id,
                    "connectionId": connection_id,
                    "serverIdentitySha256": server_hash,
                    "primaryRoute": primary,
                    "sessionIsolation": isolation,
                    "sessionTimeZone": time_zone,
                    "offsetLowerNs": lower,
                    "offsetUpperNs": upper,
                }
            )
        if expected_pool_connections is None:
            blocked.append(f"{node}:pool_connection_inventory_missing")
        elif len(valid_connection_keys) != expected_pool_connections[node]:
            blocked.append(f"{node}:pool_connection_coverage_unproven")
        server_hashes = {value[0] for value in identities.values()}
        if len(server_hashes) > 1:
            blocked.append(f"{node}:mixed_server_identity_without_route_journal")
    if not epochs:
        blocked.append("cache_epoch_observation_missing")
    epoch_hashes = sorted(
        {
            str(event.fields.get("epoch_sha256"))
            for event in epochs
            if SHA256.fullmatch(str(event.fields.get("epoch_sha256") or ""))
        }
    )
    if epochs and not epoch_hashes:
        unknown.append("cache_epoch_hash_invalid")
    if len(epoch_hashes) > 1 and not rotation_journal_present:
        blocked.append("cache_epoch_changed_without_rotation_journal")
    if not rotation_journal_present:
        blocked.append("cache_epoch_rotation_reason_unproven")
    if failures:
        overall = "FAIL"
    elif unknown:
        overall = "UNKNOWN"
    elif blocked:
        overall = "BLOCKED"
    else:
        overall = "PASS"
    return {
        "status": overall,
        "connectionsObserved": len(checks),
        "expectedPoolConnections": dict(expected_pool_connections) if expected_pool_connections is not None else None,
        "connections": checks,
        "epochHashes": epoch_hashes,
        "rotationJournalPresent": rotation_journal_present,
        "failures": sorted(set(failures)),
        "blocked": sorted(set(blocked)),
        "unknown": sorted(set(unknown)),
    }


def parse_e3_events(lines: Iterable[str], node: str = "") -> list[E3Event]:
    """Parse feature-gated projector events without trusting log order across processes."""
    events: list[E3Event] = []
    for line_number, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, Mapping):
            continue
        flattened = _flatten_trace_record(record)
        if flattened.get("message") != "e3 projector observation":
            continue
        event = flattened.get("event")
        process_id = flattened.get("process_observation_id")
        event_id = flattened.get("event_id")
        try:
            sequence = int(flattened.get("event_sequence"))
            wall_unix_ns = int(flattened.get("wall_unix_ns"))
            delta_event_id = int(flattened.get("delta_event_id"))
        except (TypeError, ValueError) as error:
            raise EvidenceError(f"invalid E3 event number at line {line_number}") from error
        if not isinstance(event, str) or event not in E3_TERMINAL_EVENTS | E3_NONTERMINAL_EVENTS | {
            "enqueue_staged",
            "claim_committed",
        }:
            raise EvidenceError(f"invalid E3 event name at line {line_number}")
        if not isinstance(process_id, str) or not SAFE_ID.fullmatch(process_id.replace("-", "_")):
            raise EvidenceError(f"missing or unsafe E3 process observation id at line {line_number}")
        if not isinstance(event_id, str) or not event_id:
            raise EvidenceError(f"missing E3 event_id at line {line_number}")
        attempts_value = flattened.get("attempts")
        attempts: Optional[int]
        if attempts_value is None:
            attempts = None
        else:
            try:
                attempts = int(attempts_value)
            except (TypeError, ValueError) as error:
                raise EvidenceError(f"invalid E3 attempts at line {line_number}") from error
            if attempts <= 0:
                raise EvidenceError(f"non-positive E3 attempts at line {line_number}")
        operation_id = flattened.get("operation_id")
        if operation_id is not None and (not isinstance(operation_id, str) or not operation_id):
            raise EvidenceError(f"invalid E3 operation_id at line {line_number}")
        events.append(
            E3Event(
                event=event,
                process_observation_id=process_id,
                sequence=sequence,
                wall_unix_ns=wall_unix_ns,
                delta_event_id=delta_event_id,
                event_id=event_id,
                operation_id=operation_id,
                attempts=attempts,
                fields=flattened,
                node=node,
            )
        )
    by_process: dict[str, list[E3Event]] = {}
    for event in events:
        by_process.setdefault(event.process_observation_id, []).append(event)
    for process_id, process_events in by_process.items():
        seen: set[int] = set()
        for event in process_events:
            if event.sequence in seen:
                raise EvidenceError(f"duplicate E3 event_sequence {event.sequence} in {process_id}")
            if event.sequence <= 0:
                raise EvidenceError(f"non-positive E3 event_sequence in {process_id}")
            seen.add(event.sequence)
    events.sort(key=lambda item: (item.process_observation_id, item.sequence))
    return events


def validate_e3_attempt_history(
    events: Sequence[E3Event],
    durable_rows: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    """Validate per-event projector history while preserving UNKNOWN outcomes.

    Process-local sequence numbers can pair a claim with its observations, but
    cannot order worker processes across a restart. Pair attempts inside each
    process epoch, then assemble the cross-process history by the durable
    attempt counter. A later process can never conceal a missing terminal from
    an earlier claim.
    """
    if not events:
        return {
            "status": "BLOCKED",
            "events": 0,
            "attempts": 0,
            "perEvent": {},
            "unknown": ["no authz_e3 events"],
        }
    grouped: dict[int, list[E3Event]] = {}
    for event in events:
        grouped.setdefault(event.delta_event_id, []).append(event)
    reports: dict[str, Any] = {}
    unknown: list[str] = []
    pending = False
    total_attempts = 0
    for delta_id, history in sorted(grouped.items()):
        claims = [item for item in history if item.event == "claim_committed"]
        if not claims:
            unknown.append(f"{delta_id}:missing_claim")
            reports[str(delta_id)] = {"status": "UNKNOWN", "attempts": 0}
            continue

        delta_unknown: list[str] = []
        event_ids = {item.event_id for item in history}
        operation_ids = {
            item.operation_id for item in history if item.operation_id is not None
        }
        if len(event_ids) != 1:
            delta_unknown.append("event_identity_drift")
        if len(operation_ids) > 1:
            delta_unknown.append("operation_identity_drift")

        attempt_values = [item.attempts for item in claims]
        if any(value is None for value in attempt_values):
            unknown.append(f"{delta_id}:claim_attempt_missing")
            reports[str(delta_id)] = {"status": "UNKNOWN", "attempts": len(claims)}
            continue
        numeric_attempts = [int(value) for value in attempt_values]
        total_attempts += len(numeric_attempts)
        sorted_attempts = sorted(numeric_attempts)
        if len(set(sorted_attempts)) != len(sorted_attempts):
            delta_unknown.append("duplicate_attempt")
        elif sorted_attempts != list(range(1, sorted_attempts[-1] + 1)):
            delta_unknown.append("attempt_history_gap")

        paired: dict[int, tuple[E3Event, E3Event]] = {}
        by_process: dict[tuple[str, str], list[E3Event]] = {}
        for event in history:
            by_process.setdefault((event.node, event.process_observation_id), []).append(event)
        for (node, process_id), process_events in sorted(by_process.items()):
            epoch = f"{node or 'unknown-node'}/{process_id}"
            open_claim: Optional[E3Event] = None
            for event in sorted(process_events, key=lambda item: item.sequence):
                if event.event == "enqueue_staged":
                    continue
                if event.event == "claim_committed":
                    if open_claim is not None:
                        delta_unknown.append(
                            f"{epoch}:attempt_{open_claim.attempts}:claim_without_terminal"
                        )
                    open_claim = event
                    continue
                if open_claim is None:
                    delta_unknown.append(f"{epoch}:{event.event}:without_open_claim")
                    continue
                if event.event_id != open_claim.event_id:
                    delta_unknown.append(
                        f"{epoch}:attempt_{open_claim.attempts}:event_identity_drift"
                    )
                if (
                    event.operation_id is not None
                    and event.operation_id != open_claim.operation_id
                ):
                    delta_unknown.append(
                        f"{epoch}:attempt_{open_claim.attempts}:operation_identity_drift"
                    )
                if event.attempts is not None and event.attempts != open_claim.attempts:
                    delta_unknown.append(
                        f"{epoch}:attempt_{open_claim.attempts}:attempt_identity_drift"
                    )
                if event.event in E3_TERMINAL_EVENTS:
                    attempt = int(open_claim.attempts)
                    if attempt in paired:
                        delta_unknown.append(f"attempt_{attempt}:multiple_terminal_pairs")
                    else:
                        paired[attempt] = (open_claim, event)
                    open_claim = None
            if open_claim is not None:
                delta_unknown.append(
                    f"{epoch}:attempt_{open_claim.attempts}:claim_without_terminal"
                )

        for attempt in sorted_attempts:
            if attempt not in paired:
                delta_unknown.append(f"attempt_{attempt}:missing_process_local_terminal")

        if not paired:
            delta_unknown.append("no_paired_attempt")
            unknown.extend(f"{delta_id}:{reason}" for reason in sorted(set(delta_unknown)))
            reports[str(delta_id)] = {
                "status": "UNKNOWN",
                "attempts": len(claims),
                "lastAttempt": sorted_attempts[-1],
            }
            continue

        final_attempt = sorted_attempts[-1]
        final_pair = paired.get(final_attempt)
        terminal = final_pair[1] if final_pair is not None else paired[max(paired)][1]
        for attempt, (_claim, attempt_terminal) in sorted(paired.items()):
            if attempt_terminal.event == "terminal_unknown" or attempt_terminal.fields.get("durable") is not True:
                delta_unknown.append(f"attempt_{attempt}:outcome_unknown")
            if attempt < final_attempt and attempt_terminal.event in {
                "publish_committed",
                "quarantine_committed",
            }:
                delta_unknown.append(
                    f"attempt_{attempt}:terminal_state_precedes_later_claim"
                )

        durable = terminal.fields.get("durable") is True
        outcome = str(terminal.fields.get("outcome") or "")
        if terminal.event == "terminal_unknown" or not durable:
            status = "UNKNOWN"
            delta_unknown.append(outcome or terminal.event)
        elif terminal.event in {"backoff_committed", "release_committed", "lease_left_to_expire"}:
            status = "PENDING"
            pending = True
        elif terminal.event == "publish_committed" and outcome == "succeeded":
            status = "PASS"
        elif terminal.event == "quarantine_committed" and outcome == "quarantined":
            status = "PASS"
        else:
            status = "UNKNOWN"
            delta_unknown.append(f"invalid_terminal:{terminal.event}:{outcome}")
        if durable_rows is not None:
            row = durable_rows.get(terminal.event_id)
            if row is None:
                status = "UNKNOWN"
                delta_unknown.append("missing_durable_row")
            else:
                row_attempts = row.get("attempts")
                try:
                    durable_attempts = int(row_attempts)
                except (TypeError, ValueError):
                    durable_attempts = None
                if durable_attempts != final_attempt:
                    status = "UNKNOWN"
                    delta_unknown.append("durable_attempt_mismatch")
                expected_status = {
                    "publish_committed": "SUCCEEDED",
                    "quarantine_committed": "QUARANTINED",
                    "backoff_committed": "PENDING",
                    "release_committed": "PENDING",
                    "lease_left_to_expire": "LEASED",
                }.get(terminal.event)
                accepted_statuses = (
                    {"LEASED", "PENDING"}
                    if expected_status == "LEASED"
                    else {expected_status}
                )
                if expected_status and row.get("status") not in accepted_statuses:
                    status = "UNKNOWN"
                    delta_unknown.append("durable_status_mismatch")
        if delta_unknown:
            status = "UNKNOWN"
            unknown.extend(f"{delta_id}:{reason}" for reason in sorted(set(delta_unknown)))
        reports[str(delta_id)] = {
            "status": status,
            "attempts": len(numeric_attempts),
            "lastAttempt": final_attempt,
            "terminal": terminal.event,
            "eventId": terminal.event_id,
            "pairedAttempts": sorted(paired),
        }
    overall = "UNKNOWN" if unknown else ("PENDING" if pending else "PASS")
    return {
        "status": overall,
        "events": len(events),
        "attempts": total_attempts,
        "perEvent": reports,
        "unknown": unknown,
    }


def events_for_request(events: Sequence[Event], request_id: str) -> list[Event]:
    selected = [event for event in events if event.request_id == request_id]
    # Never order by process-local sequence across epochs; keep epochs
    # contiguous so no downstream interval math compares restarts.
    selected.sort(key=lambda item: (item.node, item.process_observation_id, item.sequence))
    return selected


def one_event(events: Sequence[Event], name: str) -> Event:
    matches = [event for event in events if event.event == name]
    if len(matches) != 1:
        raise EvidenceError(f"expected exactly one {name}, got {len(matches)}")
    return matches[0]


def event_interval(events: Sequence[Event], start_name: str, end_name: str) -> SequenceInterval:
    start = one_event(events, start_name)
    end = one_event(events, end_name)
    return SequenceInterval(start.sequence, end.sequence)


def _events_between(
    events: Sequence[Event],
    *,
    name: str,
    after: int,
    before: int,
    observation: Optional[str] = None,
) -> list[Event]:
    selected = [
        event
        for event in events
        if event.event == name
        and after < event.sequence < before
        and (observation is None or event.fields.get("observation") == observation)
    ]
    selected.sort(key=lambda item: item.sequence)
    return selected


def _observation_pairs(
    events: Sequence[Event],
    *,
    observation: str,
    after: int,
    before: int,
) -> list[tuple[Event, Event]]:
    starts = _events_between(
        events,
        name="authoritative_read_start",
        observation=observation,
        after=after,
        before=before,
    )
    ends = _events_between(
        events,
        name="authoritative_read_end",
        observation=observation,
        after=after,
        before=before,
    )
    if len(starts) != len(ends):
        raise EvidenceError(
            f"unbalanced {observation} observations: {len(starts)} starts, {len(ends)} ends"
        )
    pairs: list[tuple[Event, Event]] = []
    for start, end in zip(starts, ends):
        if start.sequence >= end.sequence:
            raise EvidenceError(f"invalid {observation} observation ordering")
        if start.fields.get("outcome") != "started" or end.fields.get("outcome") != "ok":
            raise EvidenceError(f"unsuccessful {observation} observation")
        pairs.append((start, end))
    return pairs


def _pending_is_false(value: Any) -> bool:
    return value is False or value == 0 or str(value).strip().lower() in {
        "false",
        "some(false)",
        "0",
    }


def _final_load_source(request_events: Sequence[Event], final_start: Event, stable_end: Event) -> Event:
    candidates = [
        event
        for event in request_events
        if event.event == "evidence_load_result"
        and final_start.sequence < event.sequence < stable_end.sequence
    ]
    if len(candidates) != 1:
        raise EvidenceError(f"expected one final evidence_load_result, got {len(candidates)}")
    return candidates[0]


def final_observation_interval(request_events: Sequence[Event]) -> tuple[SequenceInterval, str]:
    final_start = one_event(request_events, "final_reload_start")
    stable_end = one_event(request_events, "stable_check_end")
    if final_start.sequence >= stable_end.sequence:
        raise EvidenceError("final reload must precede stable-check completion")
    source_event = _final_load_source(request_events, final_start, stable_end)
    source = source_event.fields.get("source")
    if source == "strict_db":
        strict_pairs = _observation_pairs(
            request_events,
            observation="strict_pending_probe",
            after=final_start.sequence,
            before=source_event.sequence,
        )
        if len(strict_pairs) != 1:
            raise EvidenceError(
                f"expected one strict_pending_probe pair in final load, got {len(strict_pairs)}"
            )
        start, end = strict_pairs[0]
        if not _pending_is_false(end.fields.get("pending")):
            raise EvidenceError("strict final load observed an unsafe pending delta")
        return SequenceInterval(start.sequence, end.sequence), str(source)
    if source in {"l1_cache", "l2_cache"}:
        manifest_pairs = _observation_pairs(
            request_events,
            observation="cache_manifest",
            after=final_start.sequence,
            before=source_event.sequence,
        )
        pending_pairs = _observation_pairs(
            request_events,
            observation="cache_pending_probe",
            after=final_start.sequence,
            before=source_event.sequence,
        )
        if len(manifest_pairs) != 2 or len(pending_pairs) != 2:
            raise EvidenceError(
                "cache final load requires exactly two manifest and two pending observations"
            )
        m0, m1 = manifest_pairs
        p0, p1 = pending_pairs
        ordered = (
            m0[1].sequence < p0[0].sequence
            and p0[1].sequence < m1[0].sequence
            and m1[1].sequence < p1[0].sequence
            and p1[1].sequence < source_event.sequence
        )
        if not ordered:
            raise EvidenceError("cache admission bracket is not m0 < p0 < m1 < p1")
        if not all(_pending_is_false(pair[1].fields.get("pending")) for pair in (p0, p1)):
            raise EvidenceError("cache admission bracket observed an unsafe pending delta")
        # The theorem's t_f is the first authoritative observation that supplies
        # the successful final evidence: m0, not the later completion of p1.
        return SequenceInterval(m0[0].sequence, m0[1].sequence), str(source)
    raise EvidenceError(f"unknown evidence source {source!r}")


def mutation_commit_interval(mutation_events: Sequence[Event]) -> SequenceInterval:
    start = one_event(mutation_events, "source_commit_start")
    end = one_event(mutation_events, "source_commit_end")
    if end.fields.get("outcome") != "committed":
        raise EvidenceError("source commit outcome is not durably proven")
    if start.node != end.node:
        raise EvidenceError("source commit interval spans multiple process logs")
    if (
        not start.process_observation_id
        or start.process_observation_id != end.process_observation_id
    ):
        raise EvidenceError("source commit interval spans multiple process epochs")
    return SequenceInterval(start.sequence, end.sequence)


def _candidate_identity(event: Event) -> tuple[Any, ...]:
    required = ("tenant_id", "card_id", "grant_id", "grant_revision", "grant_hash")
    values = tuple(event.fields.get(field) for field in required)
    if any(value in (None, "") for value in values):
        raise EvidenceError(f"{event.event} lacks exact candidate identity")
    return values


def _require_same_process(*event_groups: Sequence[Event]) -> str:
    events = [event for group in event_groups for event in group]
    nodes = {event.node for event in events if event.node}
    if len(nodes) != 1 or any(not event.node for event in events):
        raise EvidenceError("E1 sequence classification requires one same-node process log")
    epochs = {event.process_observation_id for event in events}
    if len(epochs) != 1 or any(not event.process_observation_id for event in events):
        raise EvidenceError(
            "E1 sequence classification requires one same-node process epoch "
            "(missing or mismatched process_observation_id)"
        )
    sequences = [event.sequence for event in events]
    if any(sequence <= 0 for sequence in sequences) or len(sequences) != len(set(sequences)):
        raise EvidenceError("E1 process log has invalid or duplicate event_sequence values")
    return next(iter(nodes))


def classify_e1_allow(request_events: Sequence[Event], mutation_events: Sequence[Event]) -> dict[str, Any]:
    _require_same_process(request_events, mutation_events)
    signed = one_event(request_events, "signed_context_bound")
    candidate = one_event(request_events, "candidate_match")
    final_start = one_event(request_events, "final_reload_start")
    stable = one_event(request_events, "stable_check_end")
    decision = one_event(request_events, "decision_return")
    admission = one_event(request_events, "host_admission")
    if decision.fields.get("allowed") is not True:
        raise EvidenceError("host_admission exists without an ALLOW decision")
    if stable.fields.get("stable") is not True:
        raise EvidenceError("host_admission exists without a stable final identity check")
    identity = _candidate_identity(candidate)
    if _candidate_identity(final_start) != identity or _candidate_identity(stable) != identity:
        raise EvidenceError("candidate identity changed across the final reload")
    if not (
        signed.sequence
        < candidate.sequence
        < final_start.sequence
        < stable.sequence
        < decision.sequence
        < admission.sequence
    ):
        raise EvidenceError("request event ordering is incomplete or invalid")
    final_interval, source = final_observation_interval(request_events)
    if not (final_start.sequence < final_interval.start <= final_interval.end < stable.sequence):
        raise EvidenceError("final authoritative observation is outside the final reload")
    commit = mutation_commit_interval(mutation_events)
    if admission.sequence < commit.start:
        category = "pre-commit"
        theorem_domain = False
        violation = False
    elif commit.end < final_interval.start:
        category = "post-commit-before-final-observation"
        theorem_domain = True
        violation = True
    elif final_interval.end < commit.start < admission.sequence:
        category = "post-final-observation-overlap"
        theorem_domain = False
        violation = False
    elif commit.overlaps(final_interval):
        category = "interval-overlap-unknown"
        theorem_domain = False
        violation = False
    elif signed.sequence < commit.start and commit.end < admission.sequence:
        category = "in-flight"
        theorem_domain = False
        violation = False
    else:
        category = "unclassified-unknown"
        theorem_domain = False
        violation = False
    return {
        "category": category,
        "theoremDomain": theorem_domain,
        "staleAllowViolation": violation,
        "evidenceSource": source,
        "commitInterval": {"start": commit.start, "end": commit.end},
        "finalObservationInterval": {"start": final_interval.start, "end": final_interval.end},
        "stableCheckSequence": stable.sequence,
        "hostAdmissionSequence": admission.sequence,
    }


def validate_request_terminal(request_events: Sequence[Event], http_status: int) -> dict[str, Any]:
    decision = one_event(request_events, "decision_return")
    allowed = decision.fields.get("allowed")
    reason = str(decision.fields.get("reason") or "")
    admitted = [event for event in request_events if event.event == "host_admission"]
    if http_status == 200:
        if allowed is not True or len(admitted) != 1:
            raise EvidenceError("HTTP 200 lacks one matching host_admission ALLOW")
        status = "ALLOW"
    elif http_status in {401, 403, 503}:
        if admitted:
            raise EvidenceError("non-200 request crossed host admission")
        if "AUTHORIZATION_PENDING" in reason:
            status = "PENDING"
        elif http_status in {401, 403} and allowed is False:
            status = "DENY"
        else:
            status = "UNKNOWN"
    else:
        status = "UNKNOWN"
    return {"decision": status, "reason": reason, "httpStatus": http_status}


def status(value: str) -> str:
    if value not in ALLOWED_STATUSES:
        raise EvidenceError(f"invalid evidence status {value!r}")
    return value
