#!/usr/bin/env python3
"""Run the production-profile suites registered in tests-suite/MANIFEST.toml.

The runner never provisions services, migrates databases, applies live faults,
or retries an unknown operation. Kernel fixtures and offline models retain
separate evidence scopes from real integrations and deployment campaigns.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "Docs" / "authorization-validation" / "tools"
for import_root in (TOOLS, ROOT / "scripts"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))
from model_acceptance import check_full_contract, check_tenant, check_universal
from performance_acceptance import check_criterion, check_divan

MANIFEST = ROOT / "tests-suite" / "MANIFEST.toml"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
ISOLATED_TEST_DATABASE = re.compile(r"^astral_rehearsal_[a-z0-9_]{1,47}$")
DEDICATED_MAPPING_DATABASE = re.compile(r"^sdk_identity_mapping_test_[a-z0-9_]{1,38}$")
RUST_RESULT = re.compile(
    r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out"
)
PYTHON_RESULT = re.compile(r"Ran (\d+) tests? in [0-9.]+s")
STATUSES = ("FAIL", "UNKNOWN", "BLOCKED", "PENDING", "SKIP", "PASS")
SERVICE_SETS = {
    "native-kernel": [],
    "offline-validation": [],
    "native-single-node": ["mysql"],
    "standalone-rabbit": ["mysql", "rabbitmq"],
    "distributed": ["mysql", "rabbitmq"],
    "redis-compat": ["mysql", "redis"],
    "performance-kernel": [],
    "performance-native": ["mysql"],
}
LOG_LIMIT = 64 * 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_manifest(path=MANIFEST, root=ROOT):
    with Path(path).open("rb") as stream:
        manifest = tomllib.load(stream)
    profiles = {item["id"]: item for item in manifest["profile"]}
    if len(profiles) != len(manifest["profile"]):
        raise ValueError("duplicate profile id")
    for profile_id, expected in SERVICE_SETS.items():
        if profiles.get(profile_id, {}).get("production_services") != expected:
            raise ValueError(f"production service contract differs: {profile_id}")
    if set(profiles) != set(SERVICE_SETS):
        raise ValueError("unknown production profile")
    series = {item["id"]: item for item in manifest["series"]}
    if len(series) != len(manifest["series"]):
        raise ValueError("duplicate series id")
    seen = set()
    for suite in manifest["suite"]:
        suite_id = suite["id"]
        if not SAFE_ID.fullmatch(suite_id) or suite_id in seen:
            raise ValueError(f"invalid or duplicate suite id: {suite_id}")
        seen.add(suite_id)
        profile = profiles[suite["profile"]]
        if suite["test_services"] != profile["production_services"]:
            raise ValueError(f"test/production dependency mismatch: {suite_id}")
        if not suite["series"] or any(name not in series for name in suite["series"]):
            raise ValueError(f"unknown or missing series: {suite_id}")
        if suite["scope"] not in ("component", "offline-model", "integration", "live-campaign"):
            raise ValueError(f"missing evidence scope: {suite_id}")
        if not suite.get("boundary") or not suite.get("owner"):
            raise ValueError(f"missing ownership/proof boundary: {suite_id}")
        for relative in suite["sources"]:
            source = (root / relative).resolve()
            if not source.is_relative_to(root.resolve()) or not source.exists():
                raise ValueError(f"missing or out-of-scope source: {relative}")
        if suite.get("blocked_reason"):
            if suite.get("argv"):
                raise ValueError(f"blocked campaign must not dispatch legacy argv: {suite_id}")
            continue
        argv = suite["argv"]
        if not argv or not all(isinstance(arg, str) and arg for arg in argv):
            raise ValueError(f"invalid argv: {suite_id}")
        if argv[0] not in {"cargo", "python", "bash"}:
            raise ValueError(f"unregistered command tool: {suite_id}")
        if argv[0] == "cargo" and (len(argv) < 2 or argv[1] not in {"check", "test", "clippy", "fmt", "tree", "bench"}):
            raise ValueError(f"unsupported Cargo operation: {suite_id}")
        if "--all-features" in argv or any("://" in arg for arg in argv):
            raise ValueError(f"unscoped feature or inline connection URL: {suite_id}")
        if suite["profile"] != "redis-compat" and any("redis-compat" in arg for arg in argv):
            raise ValueError(f"Redis feature outside compatibility: {suite_id}")
        if suite.get("timeout_seconds", 600) not in range(1, 3601):
            raise ValueError(f"invalid bounded timeout: {suite_id}")
        if suite["acceptance"] not in ("rust", "unittest", "model-json", "command", "dependency-tree", "criterion", "criterion-smoke", "divan"):
            raise ValueError(f"unknown acceptance contract: {suite_id}")
        if suite["acceptance"] in {"criterion", "criterion-smoke", "divan"}:
            cases = suite.get("benchmark_cases", [])
            if not cases or len(set(cases)) != len(cases):
                raise ValueError(f"missing or duplicate benchmark cases: {suite_id}")
        if "bench" in argv and suite["acceptance"] == "command":
            raise ValueError(f"benchmark requires measured-output acceptance: {suite_id}")
        if suite.get("model_contract") not in (None, "full-contract", "universal", "tenant"):
            raise ValueError(f"unknown model contract: {suite_id}")
        if suite.get("model_contract") == "full-contract" and suite.get("model_name") not in ("single", "two"):
            raise ValueError(f"missing exact model identity: {suite_id}")
        if "--no-fail-fast" in argv:
            raise ValueError(f"collection command must be fail-fast: {suite_id}")
        if suite.get("ignored_policy") == "outside-selection" and (
            not any(flag in argv for flag in ("--workspace", "--lib")) or "--ignored" in argv
        ):
            raise ValueError(f"ignored checks must retain an explicit separate selection: {suite_id}")
        if suite.get("expected_tests", suite.get("minimum_tests", 1)) < 1:
            raise ValueError(f"empty assertion contract: {suite_id}")
    manifest["profiles_by_id"] = profiles
    manifest["series_by_id"] = series
    return manifest


def select_suites(manifest, profiles=(), series=(), suite_ids=(), running=False, all_profiles=False):
    profile_ids = set(profiles)
    if profile_ids - SERVICE_SETS.keys():
        raise ValueError("unknown profile selection")
    labels = set(series)
    known_labels = set(manifest["series_by_id"]) | {"RQ", "M", "E", "MT", "PERF", "CORE", "ALL"}
    if labels - known_labels:
        raise ValueError("unknown series selection")
    selected_ids = set(suite_ids)
    if selected_ids - {suite["id"] for suite in manifest["suite"]}:
        raise ValueError("unknown suite selection")
    if all_profiles and profile_ids:
        raise ValueError("all-profiles and explicit profiles are mutually exclusive")
    if running and not all_profiles and not profile_ids and not selected_ids:
        profile_ids = {"native-kernel", "offline-validation", "performance-kernel"}

    def label_matches(suite):
        if not labels or "ALL" in labels:
            return True
        for label in suite["series"]:
            if label in labels:
                return True
            for family in labels & {"RQ", "M", "E", "MT"}:
                pattern = r"MT-E\d+" if family == "MT" else re.escape(family) + r"\d+"
                if re.fullmatch(pattern, label):
                    return True
        return False

    portable = running and not all_profiles and not selected_ids and not labels
    selected = [suite for suite in manifest["suite"]
                if (not profile_ids or suite["profile"] in profile_ids)
                and label_matches(suite)
                and (not selected_ids or suite["id"] in selected_ids)
                and (not portable or not suite.get("blocked_reason"))]
    if not selected:
        raise ValueError("empty test selection")
    return selected


def prepare_environment(suite, original):
    env = dict(original)
    profile = suite["profile"]
    services = SERVICE_SETS[profile]
    for name in ("DATABASE_URL", "REDIS_URL", "RABBITMQ_URL", "RUST_INTEGRATION_REQUIRED",
                 "ASTRAL_TEST_DATABASE_NAME", "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL",
                 "INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE", "MYSQL_ROOT_PASSWORD", "MYSQL_DATABASE",
                 "RABBITMQ_USER", "RABBITMQ_PASSWORD",
                 "COMPOSE_PROFILES", "SKIP_DOCKER", "ASTRAL_TARGET_REGION", "ASTRAL_PERF_CASE"):
        env.pop(name, None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["ASTRAL_REDIS_PROJECTION_COMPAT"] = "true" if "redis" in services else "false"
    env["ASTRAL_MESSAGE_TRANSPORT"] = "rabbit" if "rabbitmq" in services else "local"
    if profile in {"native-kernel", "performance-kernel", "offline-validation"}:
        env.pop("ASTRAL_MIGRATION_ENV", None)
    if not services:
        return env, None
    if original.get("TEST_USE_EXISTING") != "1":
        return env, "TEST_USE_EXISTING=1 is required; this runner does not provision or migrate"
    if original.get("ASTRAL_MIGRATION_ENV") != "isolated" or original.get("RUST_INTEGRATION_REQUIRED") != "1":
        return env, "isolated migration environment and required integration mode are missing"
    database_name = "DATABASE_URL"
    dedicated = suite.get("database_scope") == "identity-mapping"
    if dedicated:
        database_name = "INTEGRATION_IDENTITY_MAPPING_DATABASE_URL"
    value = original.get(database_name, "")
    try:
        parsed = urlsplit(value)
        name = unquote(parsed.path.lstrip("/"))
        valid = parsed.scheme == "mysql" and parsed.hostname in {"localhost", "127.0.0.1"} and parsed.port == 3308
        if dedicated:
            valid = valid and bool(DEDICATED_MAPPING_DATABASE.fullmatch(name)) and name == original.get("INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE")
        else:
            valid = valid and bool(ISOLATED_TEST_DATABASE.fullmatch(name)) and name == original.get("ASTRAL_TEST_DATABASE_NAME")
        valid = valid and not parsed.query and not parsed.fragment
    except ValueError:
        valid = False
    if not valid:
        return env, f"{database_name} must select the allowlisted isolated loopback database"
    env["DATABASE_URL"] = value
    env["RUST_INTEGRATION_REQUIRED"] = "1"
    env["ASTRAL_MIGRATION_ENV"] = "isolated"
    if dedicated:
        env["INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE"] = name
    else:
        env["ASTRAL_TEST_DATABASE_NAME"] = name
    for service, variable, scheme, port in (("rabbitmq", "RABBITMQ_URL", "amqp", 5673), ("redis", "REDIS_URL", "redis", 6380)):
        if service not in services:
            continue
        value = original.get(variable, "")
        try:
            parsed = urlsplit(value)
            valid = parsed.scheme == scheme and parsed.hostname in {"localhost", "127.0.0.1"} and parsed.port == port
            if service == "rabbitmq":
                valid = valid and len(parsed.path) > 1
            valid = valid and not parsed.fragment
        except ValueError:
            valid = False
        if not valid:
            return env, f"{variable} is missing its isolated loopback service or explicit vhost"
        env[variable] = value
    return env, None


def classify_output(suite, code, stdout, stderr, interrupted=False):
    combined = stdout + "\n" + stderr
    if interrupted or code in (124, 130, 137, 143) or code < 0 or re.search(r"\[(?:UNKNOWN|unknown)\]", combined):
        return {"status": "UNKNOWN", "reason": "runner interrupted, deadline exceeded or durable outcome unproven"}
    if code != 0:
        return {"status": "FAIL", "reason": f"required command exited {code}"}
    explicit_status = re.search(r"\[(PENDING|pending|BLOCKED|blocked|FAIL|fail)\]", combined)
    if explicit_status:
        status = explicit_status.group(1).upper()
        return {"status": status, "reason": f"command reported explicit [{status}] state"}
    internal_skip = bool(re.search(r"\[(?:SKIP|skip)\]", combined))
    acceptance = suite["acceptance"]
    minimum = suite.get("minimum_tests", 1)
    if acceptance == "rust":
        matches = RUST_RESULT.findall(combined)
        counts = {"passed": 0, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0}
        for outcome, *numbers in matches:
            for key, number in zip(counts, numbers):
                counts[key] += int(number)
            if outcome == "FAILED":
                counts["failed"] = max(1, counts["failed"])
        if internal_skip:
            return {"status": "SKIP", "reason": "a required Rust check returned an internal skip", "tests": counts}
        if counts["failed"] or not matches or counts["passed"] < minimum:
            return {"status": "FAIL", "reason": "missing, empty, or failing Rust assertion summary", "tests": counts}
        if "expected_tests" in suite and counts["passed"] != suite["expected_tests"]:
            return {"status": "FAIL", "reason": "exact Rust target executed an unexpected assertion count", "tests": counts}
        if counts["ignored"] and suite.get("ignored_policy") != "outside-selection":
            return {"status": "SKIP", "reason": "selected Rust target contains unexecuted ignored checks", "tests": counts}
        if suite.get("performance_cases"):
            measurements = classify_performance_matrix(suite, stdout)
            measurements["tests"] = counts
            return measurements
        return {"status": "PASS", "reason": "scoped non-ignored Rust assertions executed; ignored checks remain outside selection" if counts["ignored"] else "scoped Rust assertions executed",
                "tests": counts, "unexecuted_ignored": counts["ignored"]}
    if internal_skip:
        return {"status": "SKIP", "reason": "a required check returned an internal skip"}
    if acceptance == "unittest":
        matches = PYTHON_RESULT.findall(combined)
        count = sum(int(value) for value in matches)
        if not matches or count < minimum or not re.search(r"^OK(?:\s|$)", combined, re.MULTILINE):
            return {"status": "FAIL", "reason": "missing or empty Python assertion summary", "tests": {"executed": count}}
        skipped = re.findall(r"skipped=(\d+)", combined)
        if skipped and sum(map(int, skipped)):
            return {"status": "SKIP", "reason": "Python checks skipped", "tests": {"executed": count, "skipped": sum(map(int, skipped))}}
        return {"status": "PASS", "reason": "offline Python assertions executed", "tests": {"executed": count}}
    if acceptance == "model-json":
        try:
            model = json.loads(stdout)
            contract = suite.get("model_contract")
            if contract == "full-contract":
                return check_full_contract(model, suite["model_name"])
            if contract == "universal":
                return check_universal(model)
            if contract == "tenant":
                return check_tenant(model)
            return {"status": "FAIL", "reason": "unregistered abstract-model acceptance contract"}
        except (ValueError, KeyError, TypeError, AttributeError):
            return {"status": "UNKNOWN", "reason": "missing structured abstract-model result"}
    if acceptance in {"criterion", "criterion-smoke"}:
        return check_criterion(suite, stdout, acceptance == "criterion-smoke")
    if acceptance == "divan":
        return check_divan(suite, stdout)
    if acceptance == "dependency-tree":
        if not re.search(r"^astral-single-node v", stdout, re.MULTILINE):
            return {"status": "FAIL", "reason": "missing native default dependency tree"}
        if re.search(r"^redis v", stdout, re.MULTILINE):
            return {"status": "FAIL", "reason": "default native binary compiled a Redis dependency"}
    if suite.get("required_output") and suite["required_output"] not in combined:
        return {"status": "FAIL", "reason": "required command postcondition output is absent"}
    return {"status": "PASS", "reason": "scoped command completed; see its component proof boundary"}


def classify_performance_matrix(suite, stdout):
    raw_rows = re.findall(r"PERF_MATRIX (\{[^\n]+\})", stdout)
    try:
        rows = [json.loads(row) for row in raw_rows]
        cases = [row["case"] for row in rows]
        if len(rows) != suite["performance_cases"] or len(set(cases)) != len(cases):
            raise ValueError("missing or duplicate performance case")
        for row in rows:
            names = ("legacy", "current") if "current" in row else ("samples",)
            for name in names:
                samples = row[name]
                if len(samples) < 15 or any(
                    not isinstance(value, (int, float, list))
                    or isinstance(value, (int, float)) and (not math.isfinite(value) or value < 0)
                    or isinstance(value, list) and any(not isinstance(number, (int, float))
                        or not math.isfinite(number) or number < 0 for number in value)
                    for value in samples
                ):
                    raise ValueError("invalid or missing performance samples")
    except (ValueError, KeyError, TypeError):
        return {"status": "FAIL", "reason": "performance matrix is incomplete or malformed"}
    return {"status": "PASS", "reason": "complete CPU performance matrix measured; no HTTP/DB claim",
            "performance": {"scope": "CPU component only", "cases": len(rows), "measurements": rows}}


def snapshot_hash(root=ROOT):
    names = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, capture_output=True, check=True,
    ).stdout.split(b"\0")
    digest = hashlib.sha256()
    for raw in sorted(set(names) - {b""}):
        path = root / os.fsdecode(raw)
        digest.update(raw + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest() if path.is_file() else b"missing")
    return digest.hexdigest()


def wait_owned_process_group(process, timeout):
    deadline = time.monotonic() + timeout
    while True:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def stop_owned_process(process):
    if os.name == "nt":
        if process.poll() is not None:
            return
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       capture_output=True, timeout=15, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if not wait_owned_process_group(process, 5):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if not wait_owned_process_group(process, 15):
                raise OSError("owned process group did not exit; log integrity is unknown")
    process.wait(timeout=15)


def scrub_log(text, env):
    sensitive = ("SECRET", "PASSWORD", "TOKEN", "API_KEY", "APIKEY", "ACCESS_KEY",
                 "PRIVATE_KEY", "CREDENTIAL", "DATABASE_URL", "REDIS_URL", "RABBITMQ_URL")
    values = sorted({value for name, value in env.items()
                     if value and any(word in name.upper() for word in sensitive)}, key=len, reverse=True)
    for value in values:
        text = text.replace(value, "[redacted]")
    return re.sub(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+", "[redacted-url]", text)


def execute(suite, env, directory):
    argv = [sys.executable if arg == "python" else arg for arg in suite["argv"]]
    argv = [(ROOT / arg).as_posix() if arg.endswith(".sh") else arg for arg in argv]
    stdout_path = directory / f"{suite['id']}.stdout.log"
    stderr_path = directory / f"{suite['id']}.stderr.log"
    interrupted = False
    started = time.monotonic()
    popen_kwargs = {"cwd": ROOT, "env": env}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True
    with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, **popen_kwargs)
        try:
            while process.poll() is None:
                if time.monotonic() - started >= suite.get("timeout_seconds", 600) or stdout_path.stat().st_size + stderr_path.stat().st_size > LOG_LIMIT:
                    interrupted = True
                    stop_owned_process(process)
                    break
                time.sleep(0.05)
            if not interrupted and os.name != "nt" and not wait_owned_process_group(process, 5):
                interrupted = True
                stop_owned_process(process)
        except KeyboardInterrupt:
            interrupted = True
            stop_owned_process(process)
        except BaseException:
            stop_owned_process(process)
            raise
    if process.returncode is None:
        raise OSError("owned command has no reconciled exit status")
    stdout = scrub_log(stdout_path.read_text(encoding="utf-8", errors="replace"), env)
    stderr = scrub_log(stderr_path.read_text(encoding="utf-8", errors="replace"), env)
    stdout_bytes = stdout.encode("utf-8")
    stderr_bytes = stderr.encode("utf-8")
    stdout_path.write_bytes(stdout_bytes)
    stderr_path.write_bytes(stderr_bytes)
    verdict = classify_output(suite, process.returncode, stdout, stderr, interrupted)
    verdict.update(exit_code=process.returncode, elapsed_seconds=round(time.monotonic() - started, 3),
                   stdout=str(stdout_path), stderr=str(stderr_path),
                   log_integrity="bounded prefix only" if interrupted else "complete",
                   stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
                   stderr_sha256=hashlib.sha256(stderr_bytes).hexdigest(),
                   stream_disconnect=interrupted)
    return verdict


def fold_status(records):
    statuses = {item["status"] for item in records}
    return next((status for status in STATUSES if status in statuses), "BLOCKED")


def save_record(path, report):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_selected(manifest, suites, run_id, artifact_root, verify_items=False):
    if not SAFE_ID.fullmatch(run_id):
        raise ValueError("invalid run id")
    parent = Path(artifact_root).resolve()
    if parent.is_relative_to(ROOT):
        raise ValueError("evidence must be outside the tracked workspace")
    directory = parent / run_id
    directory.mkdir(parents=True, exist_ok=False)
    frozen = snapshot_hash()
    report = {"schema_version": 2, "taskId": run_id, "run_id": run_id,
              "delegated": False, "responsible_agent": "test_campaign", "cwd": str(ROOT),
              "environment": {"python": sys.version.split()[0], "platform": sys.platform},
              "started_at": utc_now(), "source_sha256": frozen, "status": "PENDING",
              "retries": 0, "provisioning": "none; pre-migrated approved dependencies only",
              "selection": [suite["id"] for suite in suites], "results": [], "item_results": [],
              "verify_items": verify_items, "phase_timing_seconds": [],
              "rerun_policy": "fix or reconcile the first non-PASS target; rerun the full original selection with a new run id; no cached PASS reuse"}
    path = directory / "result.json"
    save_record(path, report)
    preflight = []
    for suite in suites:
        problem = suite.get("blocked_reason")
        if not problem:
            _, problem = prepare_environment(suite, os.environ)
            executable = sys.executable if suite["argv"][0] == "python" else suite["argv"][0]
            if not problem and not shutil.which(executable):
                problem = f"required tool unavailable: {executable}"
        if problem:
            preflight.append({"id": suite["id"], "reason": problem})
    report["preflight"] = {"status": "BLOCKED" if preflight else "PASS", "issues": preflight}
    selected_ids = {suite["id"] for suite in suites}
    report["outside_selection"] = [
        {"id": suite["id"], "profile": suite["profile"], "executed": False,
         "reason": suite.get("blocked_reason", "outside the explicit production-profile selection")}
        for suite in manifest.get("suite", []) if suite["id"] not in selected_ids
    ]
    stop = None
    campaign_started = time.monotonic()
    for phase in (["items", "collection"] if verify_items else ["collection"]):
        phase_directory = directory / phase
        phase_directory.mkdir()
        records = report["item_results"] if phase == "items" else report["results"]
        for suite in suites:
            record = {"taskId": f"{run_id}:{phase}:{suite['id']}", "id": suite["id"], "phase": phase,
                      "profile": suite["profile"], "series": suite["series"], "scope": suite["scope"], "owner": suite["owner"],
                      "production_services": SERVICE_SETS[suite["profile"]], "test_services": suite["test_services"],
                      "boundary": suite["boundary"], "argv": suite.get("argv", []), "cwd": str(ROOT),
                      "started_at": None, "retries": 0, "expected_postcondition": suite.get("acceptance", "live evidence"),
                      "exit_code": None, "stdout": None, "stderr": None, "log_integrity": "not started", "stream_disconnect": False}
            if preflight:
                problem = next((entry["reason"] for entry in preflight if entry["id"] == suite["id"]),
                               "collection preflight failed; no suites dispatched")
                record.update(status="BLOCKED", reason=problem)
            elif stop:
                record.update(status="BLOCKED", reason=f"prior {stop['status']} in {stop['id']}; fix or reconcile before a fresh full collection")
            else:
                env, problem = prepare_environment(suite, os.environ)
                executable = sys.executable if suite["argv"][0] == "python" else suite["argv"][0]
                env["CRITERION_HOME"] = str(phase_directory / "criterion" / suite["id"])
                record["environment_names"] = sorted(name for name in env if name in {
                    "DATABASE_URL", "REDIS_URL", "RABBITMQ_URL", "RUST_INTEGRATION_REQUIRED",
                    "ASTRAL_TEST_DATABASE_NAME", "ASTRAL_REDIS_PROJECTION_COMPAT",
                    "ASTRAL_MESSAGE_TRANSPORT", "ASTRAL_MIGRATION_ENV"})
                if problem or not shutil.which(executable):
                    record.update(status="BLOCKED", reason=problem or f"required tool unavailable: {executable}")
                elif snapshot_hash() != frozen:
                    record.update(status="UNKNOWN", reason="source changed after freeze; evidence belongs to another snapshot")
                else:
                    record.update(status="PENDING", reason="command dispatched; result not yet proven", started_at=utc_now(),
                                  stdout=str(phase_directory / f"{suite['id']}.stdout.log"),
                                  stderr=str(phase_directory / f"{suite['id']}.stderr.log"),
                                  log_integrity="in progress; terminal integrity not yet proven")
                    records.append(record)
                    report["status"] = "PENDING"
                    save_record(path, report)
                    try:
                        record.update(execute(suite, env, phase_directory))
                    except KeyboardInterrupt:
                        record.update(status="UNKNOWN", reason="campaign interrupted; reconcile the owned process and any durable state")
                    except (OSError, subprocess.SubprocessError) as error:
                        record.update(status="UNKNOWN", reason=f"runner/log interrupted: {type(error).__name__}",
                                      stdout=str(phase_directory / f"{suite['id']}.stdout.log"),
                                      stderr=str(phase_directory / f"{suite['id']}.stderr.log"),
                                      log_integrity="unknown; reconcile owned process and artifacts", stream_disconnect=True)
                    if snapshot_hash() != frozen:
                        record.update(status="UNKNOWN", reason="source changed while required command was running")
            if not records or records[-1] is not record:
                records.append(record)
            record["finished_at"] = utc_now()
            record["actual_postcondition"] = record["reason"]
            report["phase_timing_seconds"].append({"id": suite["id"], "phase": phase,
                "finished_at_monotonic_offset": round(time.monotonic() - campaign_started, 3)})
            if record["status"] != "PASS" and stop is None:
                stop = {"id": suite["id"], "status": record["status"], "phase": phase}
                report["stopped_at"] = stop
            report["status"] = stop["status"] if stop else "PENDING"
            save_record(path, report)
            print(f"[{record['status']}] {phase}/{suite['id']} ({suite['profile']}/{suite['scope']}): {record['reason']}", flush=True)
    report["finished_at"] = utc_now()
    report["elapsed_seconds"] = round(time.monotonic() - campaign_started, 3)
    report["status"] = stop["status"] if stop else fold_status(report["item_results"] + report["results"])
    report["series_results"] = [
        {"id": label, "status": fold_status([item for item in report["results"] if label in item["series"]]),
         "coverage": "selected suites only; not full campaign acceptance",
         "scopes": sorted({item["scope"] for item in report["results"] if label in item["series"]}),
         "boundary": manifest["series_by_id"][label]["boundary"],
         "suites": [item["id"] for item in report["results"] if label in item["series"]]}
        for label in manifest["series_by_id"] if any(label in item["series"] for item in report["results"])
    ]
    save_record(path, report)
    print(f"[{report['status']}] evidence: {path}")
    return 0 if report["status"] == "PASS" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--list", action="store_true", help="read-only inventory (default)")
    mode.add_argument("--run", action="store_true", help="execute the portable kernel/offline/CPU collection by default")
    parser.add_argument("--verify-items", action="store_true", help="verify each suite first, then rerun the full same-snapshot collection without cached results")
    parser.add_argument("--profile", action="append", default=[], choices=sorted(SERVICE_SETS))
    parser.add_argument("--all-profiles", action="store_true", help="select every registered suite; preflight blocks the whole collection if any prerequisite is missing")
    parser.add_argument("--series", action="append", default=[])
    parser.add_argument("--suite", action="append", default=[])
    parser.add_argument("--json", action="store_true", help="structured inventory")
    parser.add_argument("--run-id", default=f"test-campaign-{time.time_ns()}-{os.getpid()}")
    parser.add_argument("--artifact-root", default=tempfile.gettempdir())
    args = parser.parse_args(argv)
    try:
        manifest = read_manifest()
        selected = select_suites(manifest, args.profile, args.series, args.suite, args.run, args.all_profiles)
        if args.run:
            return run_selected(manifest, selected, args.run_id, args.artifact_root, args.verify_items)
        if args.json:
            print(json.dumps({"profiles": manifest["profile"], "series": manifest["series"], "suites": selected}, indent=2, ensure_ascii=False))
        else:
            for suite in selected:
                state = "BLOCKED" if suite.get("blocked_reason") else "AVAILABLE"
                print(f"{suite['id']} | {suite['profile']} | {','.join(suite['series'])} | {suite['scope']} | {state}")
        return 0
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"[BLOCKED] invalid inventory or runner precondition: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
