#!/usr/bin/env python3
"""In-network performance workload for the TDSC isolated Compose topology.

Evidence contains only timings, status classes, and configuration. Runtime
credentials, endpoint addresses, HTTP bodies, and tokens remain in memory.
"""

import csv
import hashlib
import json
import math
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA_VERSION = 1
PROTECTED_PATH = "/main/api/v1/permission-rules/registry"
LOGIN_PATH = "/api/v1/auth/login"
REGISTER_PATH = "/api/v1/auth/register"
SAMPLE_FIELDS = (
    "replicate",
    "concurrency",
    "worker",
    "sequence",
    "outcome",
    "status",
    "latency_ns",
    "latency_ms",
)


class DriverError(RuntimeError):
    """Raised for invalid configuration or workload setup failures."""


def require_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise DriverError("Missing required environment variable: {0}".format(name))
    return value


def positive_int_environment(name: str, default: int, minimum: int = 1) -> int:
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as error:
        raise DriverError("{0} must be an integer.".format(name)) from error
    if value < minimum:
        raise DriverError("{0} must be at least {1}.".format(name, minimum))
    return value


def parse_concurrencies(raw_value: str) -> List[int]:
    if not raw_value or raw_value.strip() != raw_value:
        raise DriverError("TDSC_PERF_CONCURRENCIES must be a comma-separated list without surrounding whitespace.")
    values: List[int] = []
    for entry in raw_value.split(","):
        if not entry or not entry.isdigit():
            raise DriverError("TDSC_PERF_CONCURRENCIES must contain positive decimal integers.")
        value = int(entry)
        if value < 1:
            raise DriverError("TDSC_PERF_CONCURRENCIES must contain positive decimal integers.")
        if value in values:
            raise DriverError("TDSC_PERF_CONCURRENCIES must not contain duplicate values.")
        values.append(value)
    return values


def percentile(values: Sequence[float], percent: float) -> Optional[float]:
    """Return a linearly interpolated percentile, or None for no observations."""
    if not values:
        return None
    if not 0.0 <= percent <= 100.0:
        raise ValueError("percent must be between 0 and 100")
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * (percent / 100.0)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def mean_and_sample_sd(values: Sequence[float]) -> Dict[str, Optional[float]]:
    if not values:
        return {"mean": None, "sampleSd": None}
    result: Dict[str, Optional[float]] = {"mean": statistics.fmean(values), "sampleSd": None}
    if len(values) > 1:
        result["sampleSd"] = statistics.stdev(values)
    else:
        result["sampleSd"] = 0.0
    return result


def classify_status(status: Optional[int]) -> str:
    if status is None or status == 0:
        return "transport_error"
    if 200 <= status < 400:
        return "success"
    if 400 <= status < 500:
        return "http_4xx"
    if 500 <= status < 600:
        return "http_5xx"
    return "transport_error"


def is_timeout_error(error: Exception) -> bool:
    if isinstance(error, (socket.timeout, TimeoutError)):
        return True
    if isinstance(error, urllib.error.URLError):
        return is_timeout_error(error.reason)
    return False


def classify_exception(error: Exception) -> Tuple[str, Optional[int]]:
    if isinstance(error, urllib.error.HTTPError):
        return classify_status(error.code), error.code
    if is_timeout_error(error):
        return "timeout", None
    return "transport_error", None


def sample_row(
    replicate: int,
    concurrency: int,
    worker: int,
    sequence: int,
    outcome: str,
    status: Optional[int],
    latency_ns: int,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "replicate": replicate,
        "concurrency": concurrency,
        "worker": worker,
        "sequence": sequence,
        "outcome": outcome,
        "status": "" if status is None else status,
        "latency_ns": latency_ns,
        "latency_ms": "{0:.6f}".format(latency_ns / 1_000_000.0),
    }
    validate_sample_row(row)
    return row


def validate_sample_row(row: Dict[str, Any]) -> None:
    if tuple(row.keys()) != SAMPLE_FIELDS:
        raise ValueError("sample row does not match the evidence schema")
    if row["outcome"] not in {"success", "http_4xx", "http_5xx", "transport_error", "timeout"}:
        raise ValueError("unknown sample outcome")
    if any(not isinstance(row[name], int) or row[name] < 1 for name in ("replicate", "concurrency", "worker", "sequence")):
        raise ValueError("replicate, concurrency, worker, and sequence must be positive integers")
    if not isinstance(row["latency_ns"], int) or row["latency_ns"] < 0:
        raise ValueError("latency_ns must be a non-negative integer")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    with path.open("w", newline="", encoding="ascii") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, document: Dict[str, Any]) -> None:
    with path.open("w", encoding="ascii", newline="\n") as stream:
        json.dump(document, stream, indent=2, sort_keys=True, ensure_ascii=True)
        stream.write("\n")


def request_json(url: str, payload: Dict[str, Any], timeout_seconds: float) -> Tuple[int, Dict[str, Any]]:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status = response.getcode()
            body = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()
    try:
        decoded = json.loads(body.decode("utf-8")) if body else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError("Bootstrap endpoint returned a non-JSON response.") from error
    return status, decoded


def runtime_fixture_identifiers(run_id: str, seed: str, concurrency: int, replicate: int) -> Dict[str, str]:
    material = "{0}:{1}:performance:{2}:{3}".format(run_id, seed, concurrency, replicate)
    digest = hashlib.sha256(material.encode("ascii")).hexdigest()
    numeric_phone = "18{0:09d}".format(int(digest[:16], 16) % 1_000_000_000)
    suffix = digest[:18]
    return {
        "phone": numeric_phone,
        "username": "tdsc_perf_{0}".format(suffix),
        "password": "P_{0}_pw".format(suffix),
        "deviceId": "tdsc-perf-{0}".format(suffix),
    }


def extract_login_fixture(login_document: Dict[str, Any]) -> Tuple[str, int]:
    data = login_document.get("data")
    if not isinstance(data, dict):
        raise DriverError("Login response did not include a data object.")
    token = data.get("accessToken")
    user = data.get("user")
    card = data.get("currentCard")
    if not isinstance(token, str) or not token:
        raise DriverError("Login response did not include an access token.")
    if not isinstance(user, dict) or not isinstance(card, dict):
        raise DriverError("Login response did not include user and current-card data.")
    card_id = card.get("cardId")
    if isinstance(card_id, bool) or not isinstance(card_id, int) or card_id < 1:
        raise DriverError("Login response did not include a valid current-card identifier.")
    return token, card_id


def seed_permission_fixture(db: Dict[str, str], card_id: int) -> None:
    statement = (
        "INSERT INTO permission_rule "
        "(card_id, resource_type, action_code, effect, priority, source_type, enabled, created_at, updated_at) "
        "VALUES ({0}, 'permission_rule', 'read', 'ALLOW', 0, 'TDSC_PERF_FIXTURE', 1, NOW(), NOW())"
    ).format(card_id)
    environment = os.environ.copy()
    environment["MYSQL_PWD"] = db["password"]
    completed = subprocess.run(
        [
            "mariadb",
            "--protocol=TCP",
            "--host={0}".format(db["host"]),
            "--port={0}".format(db["port"]),
            "--user={0}".format(db["username"]),
            "--database={0}".format(db["name"]),
            "--batch",
            "--skip-column-names",
            "--raw",
            "--execute",
            statement,
        ],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise DriverError("Unable to create the runtime permission fixture.")


def wait_for_gateway(base_url: str, timeout_seconds: float) -> None:
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            status, _ = request_json(
                base_url + LOGIN_PATH,
                {"username": "not-ready", "password": "not-ready"},
                timeout_seconds,
            )
            if status not in {0, 502, 503, 504}:
                return
        except (DriverError, OSError, urllib.error.URLError):
            pass
        time.sleep(2.0)
    raise DriverError("Gateway did not become reachable during the performance readiness window.")


def bootstrap_replicate(
    base_url: str,
    run_id: str,
    seed: str,
    concurrency: int,
    replicate: int,
    timeout_seconds: float,
    db: Dict[str, str],
) -> str:
    identifiers = runtime_fixture_identifiers(run_id, seed, concurrency, replicate)
    register_status, _ = request_json(
        base_url + REGISTER_PATH,
        {
            "phone": identifiers["phone"],
            "username": identifiers["username"],
            "password": identifiers["password"],
            "displayName": "TDSC Performance",
        },
        timeout_seconds,
    )
    if not 200 <= register_status < 300:
        raise DriverError("Runtime user registration failed for a performance replicate.")
    login_status, login_document = request_json(
        base_url + LOGIN_PATH,
        {
            "username": identifiers["username"],
            "password": identifiers["password"],
            "deviceId": identifiers["deviceId"],
        },
        timeout_seconds,
    )
    if not 200 <= login_status < 300:
        raise DriverError("Runtime user login failed for a performance replicate.")
    token, card_id = extract_login_fixture(login_document)
    seed_permission_fixture(db, card_id)
    return token


def make_protected_request(base_url: str, token: str, timeout_seconds: float) -> Tuple[str, Optional[int], int]:
    request = urllib.request.Request(
        base_url + PROTECTED_PATH,
        method="GET",
        headers={"Authorization": "Bearer {0}".format(token)},
    )
    started_ns = time.monotonic_ns()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status = response.getcode()
            response.read()
        return classify_status(status), status, time.monotonic_ns() - started_ns
    except Exception as error:  # Every failed call must have one outcome class.
        outcome, status = classify_exception(error)
        return outcome, status, time.monotonic_ns() - started_ns


def run_workers(
    base_url: str,
    token: str,
    concurrency: int,
    replicate: int,
    calls_per_worker: int,
    timeout_seconds: float,
    record_samples: bool,
) -> List[Dict[str, Any]]:
    barrier = threading.Barrier(concurrency + 1)
    rows: List[Dict[str, Any]] = []
    rows_lock = threading.Lock()

    def worker(worker_number: int) -> None:
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            return
        local_rows: List[Dict[str, Any]] = []
        for sequence in range(1, calls_per_worker + 1):
            outcome, status, latency_ns = make_protected_request(base_url, token, timeout_seconds)
            if record_samples:
                local_rows.append(
                    sample_row(replicate, concurrency, worker_number, sequence, outcome, status, latency_ns)
                )
        if record_samples:
            with rows_lock:
                rows.extend(local_rows)

    threads = [threading.Thread(target=worker, args=(worker_number,)) for worker_number in range(1, concurrency + 1)]
    for thread in threads:
        thread.start()
    try:
        barrier.wait()
    except threading.BrokenBarrierError as error:
        raise DriverError("Worker barrier failed before the workload began.") from error
    for thread in threads:
        thread.join()
    rows.sort(key=lambda row: (int(row["worker"]), int(row["sequence"])))
    return rows


def outcome_counts(rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts = {name: 0 for name in ("success", "http_4xx", "http_5xx", "transport_error", "timeout")}
    for row in rows:
        counts[str(row["outcome"])] += 1
    return counts


def replicate_summary(
    rows: Sequence[Dict[str, Any]],
    replicate: int,
    concurrency: int,
    elapsed_ns: int,
) -> Dict[str, Any]:
    latencies_ms = [int(row["latency_ns"]) / 1_000_000.0 for row in rows]
    counts = outcome_counts(rows)
    total = len(rows)
    success_rate = counts["success"] / total if total else 0.0
    error_rate = 1.0 - success_rate
    elapsed_seconds = elapsed_ns / 1_000_000_000.0
    return {
        "replicate": replicate,
        "concurrency": concurrency,
        "sampleCount": total,
        "successfulCount": counts["success"],
        "errorCount": total - counts["success"],
        "elapsedNs": elapsed_ns,
        "throughputQps": total / elapsed_seconds if elapsed_seconds > 0 else 0.0,
        "successQps": counts["success"] / elapsed_seconds if elapsed_seconds > 0 else 0.0,
        "successRate": success_rate,
        "errorRate": error_rate,
        "p50Ms": percentile(latencies_ms, 50.0),
        "p95Ms": percentile(latencies_ms, 95.0),
        "p99Ms": percentile(latencies_ms, 99.0),
        "outcomes": counts,
    }


def concurrency_summary(replicates: Sequence[Dict[str, Any]], concurrency: int) -> Dict[str, Any]:
    metrics = {
        "throughputQps": [float(item["throughputQps"]) for item in replicates],
        "successQps": [float(item["successQps"]) for item in replicates],
        "successRate": [float(item["successRate"]) for item in replicates],
        "errorRate": [float(item["errorRate"]) for item in replicates],
        "p50Ms": [float(item["p50Ms"]) for item in replicates if item["p50Ms"] is not None],
        "p95Ms": [float(item["p95Ms"]) for item in replicates if item["p95Ms"] is not None],
        "p99Ms": [float(item["p99Ms"]) for item in replicates if item["p99Ms"] is not None],
    }
    combined_outcomes = {name: 0 for name in ("success", "http_4xx", "http_5xx", "transport_error", "timeout")}
    for item in replicates:
        for outcome, count in item["outcomes"].items():
            combined_outcomes[outcome] += int(count)
    return {
        "concurrency": concurrency,
        "replicateCount": len(replicates),
        "sampleCount": sum(int(item["sampleCount"]) for item in replicates),
        "outcomes": combined_outcomes,
        "replicateLevelMetrics": {name: mean_and_sample_sd(values) for name, values in metrics.items()},
    }


def main() -> int:
    evidence_dir = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_id = require_environment("TDSC_RUN_ID")
    seed = require_environment("TDSC_SEED")
    base_url = require_environment("GATEWAY_BASE_URL").rstrip("/")
    reps = positive_int_environment("TDSC_PERF_REPS", 5)
    warmup_per_worker = positive_int_environment("TDSC_PERF_WARMUP", 20, minimum=0)
    samples_per_worker = positive_int_environment("TDSC_PERF_SAMPLES", 200)
    timeout_seconds = float(os.environ.get("TDSC_PERF_TIMEOUT_SECONDS", "30"))
    if timeout_seconds <= 0:
        raise DriverError("TDSC_PERF_TIMEOUT_SECONDS must be positive.")
    concurrencies = parse_concurrencies(os.environ.get("TDSC_PERF_CONCURRENCIES", "1,4,8,16,32"))
    db = {
        "host": require_environment("DB_HOST"),
        "port": require_environment("DB_PORT"),
        "name": require_environment("DB_NAME"),
        "username": require_environment("DB_USERNAME"),
        "password": require_environment("DB_PASSWORD"),
    }

    write_json(
        evidence_dir / "perf-method.json",
        {
            "formatVersion": SCHEMA_VERSION,
            "runId": run_id,
            "driver": "protocol-runner/run-performance.py",
            "concurrencies": concurrencies,
            "replicatesPerConcurrency": reps,
            "warmupRequestsPerWorkerPerReplicate": warmup_per_worker,
            "timedRequestsPerWorkerPerReplicate": samples_per_worker,
            "timingClock": "time.monotonic_ns",
            "latencyScope": "Client-observed protected-endpoint request duration, from immediately before urllib.request.urlopen until response body consumption or exception.",
            "synchronization": "threading.Barrier releases all workers for each independent timed replicate",
            "outcomeClasses": ["success", "http_4xx", "http_5xx", "transport_error", "timeout"],
            "rawSampleSchema": list(SAMPLE_FIELDS),
        },
    )

    wait_for_gateway(base_url, timeout_seconds)
    raw_rows: List[Dict[str, Any]] = []
    replicate_rows: List[Dict[str, Any]] = []
    for concurrency in concurrencies:
        for replicate in range(1, reps + 1):
            token = bootstrap_replicate(base_url, run_id, seed, concurrency, replicate, timeout_seconds, db)
            run_workers(
                base_url,
                token,
                concurrency,
                replicate,
                warmup_per_worker,
                timeout_seconds,
                record_samples=False,
            )
            started_ns = time.monotonic_ns()
            rows = run_workers(
                base_url,
                token,
                concurrency,
                replicate,
                samples_per_worker,
                timeout_seconds,
                record_samples=True,
            )
            elapsed_ns = time.monotonic_ns() - started_ns
            write_csv(evidence_dir / "perf-replicate-c{0}-r{1}.csv".format(concurrency, replicate), rows, SAMPLE_FIELDS)
            raw_rows.extend(rows)
            replicate_rows.append(replicate_summary(rows, replicate, concurrency, elapsed_ns))

    write_csv(evidence_dir / "perf-samples.csv", raw_rows, SAMPLE_FIELDS)
    replicate_fields = (
        "replicate",
        "concurrency",
        "sampleCount",
        "successfulCount",
        "errorCount",
        "elapsedNs",
        "throughputQps",
        "successQps",
        "successRate",
        "errorRate",
        "p50Ms",
        "p95Ms",
        "p99Ms",
        "outcomes",
    )
    csv_replicates = []
    for row in replicate_rows:
        encoded = dict(row)
        encoded["outcomes"] = json.dumps(row["outcomes"], sort_keys=True, separators=(",", ":"))
        csv_replicates.append(encoded)
    write_csv(evidence_dir / "perf-replicate-summary.csv", csv_replicates, replicate_fields)

    summaries = []
    for concurrency in concurrencies:
        summaries.append(concurrency_summary([row for row in replicate_rows if row["concurrency"] == concurrency], concurrency))
    write_json(
        evidence_dir / "perf-summary.json",
        {
            "formatVersion": SCHEMA_VERSION,
            "runId": run_id,
            "summaryUnit": "independent replicate per concurrency",
            "latencyScope": "Each percentile is computed from all timed client-observed protected-endpoint requests within one replicate; aggregate percentile statistics summarize those replicate percentiles.",
            "replicates": replicate_rows,
            "concurrencySummaries": summaries,
            "limitations": [
                "The timed request unit is one protected endpoint call; TDSC_PERF_SAMPLES is interpreted as requests per worker per replicate.",
                "Summary means and sample standard deviations use independent replicate values, not individual HTTP requests; no confidence interval is estimated by this driver.",
                "Barrier synchronization coordinates client workers but cannot eliminate scheduler and network-stack start skew.",
                "Availability and dependency interruption claims are measured by the fault probe and host-side orchestrator, not by this performance workload.",
            ],
        },
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DriverError, ValueError) as error:
        print("Performance driver failed: {0}".format(error), file=sys.stderr)
        raise SystemExit(1)
