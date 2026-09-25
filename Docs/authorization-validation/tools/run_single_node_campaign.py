#!/usr/bin/env python3
"""Freeze the authorization validation single-machine E1/E2 evidence campaign.

This runner performs only local build/test checks. It never starts services,
containers, migrations, or remote nodes. Infrastructure-backed E1/E3/E4
scenarios remain BLOCKED when the isolated runtime is unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from experiment_common import atomic_json, verify_checksums, write_checksums

PREVIOUS_ATTEMPT = {
    "campaignId": "authz-validation-20260919-single-node-005",
    "status": "BLOCKED",
    "localReady": "PASS",
    "reason": (
        "Superseded: 005 executed only the five E2 exact tests as runtime "
        "evidence; the successor snapshot additionally executes the four "
        "offline Rust runtime suites. 005 is retained as an immutable snapshot."
    ),
}
DEFAULT_REPO = Path(__file__).resolve().parents[3]
REPO = Path(os.environ.get("ASTRAL_REPO_ROOT", str(DEFAULT_REPO))).expanduser().resolve()
RUST = REPO
EVIDENCE_ROOT = REPO / "Docs" / "authorization-validation" / "evidence"
SAFE_CAMPAIGN_ID = re.compile(r"^authz-validation-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
OUT: Path
LOGS: Path

COMMANDS: list[dict[str, Any]] = [
    {
        "id": "fmt-check",
        "argv": ["cargo", "fmt", "--manifest-path", str(RUST / "Cargo.toml"), "--all", "--", "--check"],
        "required": True,
    },
    {
        "id": "workspace-check",
        "argv": ["cargo", "check", "--manifest-path", str(RUST / "Cargo.toml"), "--workspace", "--all-targets"],
        "required": True,
    },
    {
        "id": "workspace-clippy",
        "argv": ["cargo", "clippy", "--manifest-path", str(RUST / "Cargo.toml"), "--workspace", "--all-targets", "--", "-D", "warnings"],
        "required": True,
    },
    {
        "id": "e1-feature-check",
        "argv": ["cargo", "check", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-trustgraph", "--all-targets", "--features", "e1-observability"],
        "required": True,
    },
    {
        "id": "e1-feature-production-clippy",
        "argv": ["cargo", "clippy", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-trustgraph", "--lib", "--bins", "--features", "e1-observability", "--", "-D", "warnings"],
        "required": True,
    },
    {
        "id": "e1-policy-engine-feature-tests-build",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "policy-engine", "--lib", "--features", "e1-observability", "--no-run"],
        "required": True,
    },
    {
        "id": "e1-astral-db-build",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-db", "--lib", "--features", "e1-observability", "--no-run"],
        "required": True,
    },
    {
        "id": "e2-pending-probe-omission",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-db", "evidence_cache::tests::e2_pending_probe_omission_accepts_stale_candidate_while_full_contract_reloads", "--lib", "--", "--exact", "--nocapture"],
        "required": True,
        "expected": "1 passed; 0 failed",
    },
    {
        "id": "e2-cache-post-recheck-omission",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-db", "evidence_cache::tests::e2_post_recheck_omission_accepts_interleaving_while_full_contract_reloads", "--lib", "--", "--exact", "--nocapture"],
        "required": True,
        "expected": "1 passed; 0 failed",
    },
    {
        "id": "e2-exact-identity-omission",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "policy-engine", "engine::tests::test_strict_successor_revision_cannot_replace_original_candidate", "--lib", "--", "--exact", "--nocapture"],
        "required": True,
        "expected": "1 passed; 0 failed",
    },
    {
        "id": "e2-final-reload-omission",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "policy-engine", "engine::tests::e2_final_reload_omission_accepts_removed_candidate_while_full_contract_reloads", "--lib", "--", "--exact"],
        "required": True,
        "expected": "1 passed; 0 failed",
    },
    {
        "id": "e2-generation-revoke-fence-omission",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-db", "evidence_cache::tests::e2_generation_revoke_fence_omission_accepts_stale_candidate", "--lib", "--", "--exact"],
        "required": True,
        "expected": "1 passed; 0 failed",
    },
    {
        "id": "runtime-policy-engine-lib",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "policy-engine", "--lib", "--features", "e1-observability"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "runtime-astral-db-lib",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-db", "--lib", "--features", "e1-observability"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "runtime-astral-common-gateway-contract",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-common", "--test", "gateway_contract_tests"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "runtime-astral-trustgraph-lib",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-trustgraph", "--lib", "--features", "e1-observability,e3-observability,e4-observability"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "experiment-feature-check",
        "argv": ["cargo", "check", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-trustgraph", "--all-targets", "--features", "e1-observability,e3-observability,e4-observability"],
        "required": True,
    },
    {
        "id": "experiment-feature-clippy",
        "argv": ["cargo", "clippy", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "astral-trustgraph", "--all-targets", "--features", "e1-observability,e3-observability,e4-observability", "--", "-D", "warnings"],
        "required": True,
    },
    {
        "id": "offline-python-tests",
        "argv": ["python", "-m", "unittest", "discover", "-s", str(TOOLS), "-p", "test_*.py"],
        "required": True,
        "expectedStderr": "OK",
        "minimumPythonTests": 1,
    },
    {
        "id": "workspace-test-compile",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "--workspace", "--no-run"],
        "required": True,
    },
    {
        "id": "e5-bounded-model",
        "argv": ["python", str(TOOLS / "e5_model_check.py"), "--max-steps", "28", "--json"],
        "required": True,
        "assertE5AbstractModel": True,
    },
]

HASHED_SOURCES = [
    "Cargo.toml",
    "Cargo.lock",
    "policy-engine/Cargo.toml",
    "policy-engine/src/e1_observation.rs",
    "policy-engine/src/engine.rs",
    "policy-engine/src/hit_stats.rs",
    "policy-engine/src/lib.rs",
    "astral-db/Cargo.toml",
    "astral-db/src/authorization_projection_repository.rs",
    "astral-db/src/evidence_cache.rs",
    "astral-db/src/permission_query.rs",
    "astral-db/tests/authorization_projection_integration.rs",
    "astral-trustgraph/Cargo.toml",
    "astral-trustgraph/src/observability.rs",
    "astral-trustgraph/src/lib.rs",
    "astral-trustgraph/src/api/permission_check.rs",
    "astral-trustgraph/src/main.rs",
    "astral-trustgraph/src/repository/rule_set_repository.rs",
    "astral-trustgraph/src/service/authorization_projector.rs",
    "astral-trustgraph/src/service/sync_publish.rs",
    "Docs/authorization-validation/VALIDATION_PROTOCOL.md",
    "Docs/authorization-validation/EVIDENCE_BOUNDARY_MATRIX.md",
    "Docs/规范/BACKEND_STANDARD.md",
    "astral-common/Cargo.toml",
    "astral-common/src/audit.rs",
    "astral-common/src/experiment_observation.rs",
    "astral-common/src/lib.rs",
    "astral-common/src/middleware/permission_check_shared.rs",
    "astral-db/src/cache_epoch.rs",
    "astral-db/src/grant_repository.rs",
    "astral-db/src/lib.rs",
    "Docs/authorization-validation/tools/experiment_common.py",
    "Docs/authorization-validation/tools/test_experiment_common.py",
    "Docs/authorization-validation/tools/e3_e4.py",
    "Docs/authorization-validation/tools/test_e3_e4.py",
    "Docs/authorization-validation/tools/node_adapter.py",
    "Docs/authorization-validation/tools/test_node_adapter.py",
    "Docs/authorization-validation/tools/e1_runner.py",
    "Docs/authorization-validation/tools/test_e1_runner.py",
    "Docs/authorization-validation/tools/lifecycle_reducer.py",
    "Docs/authorization-validation/tools/test_lifecycle_reducer.py",
    "Docs/authorization-validation/tools/e3_runner.py",
    "Docs/authorization-validation/tools/test_e3_runner.py",
    "Docs/authorization-validation/tools/e4_fault_driver.py",
    "Docs/authorization-validation/tools/test_e4_fault_driver.py",
    "Docs/authorization-validation/tools/e5_model_check.py",
    "Docs/authorization-validation/tools/test_e5_model_check.py",
    "Docs/authorization-validation/tools/run_single_node_campaign.py",
    "Docs/authorization-validation/tools/test_run_single_node_campaign.py",
    "Docs/authorization-validation/formal/AdmissionSafety.tla",
    "Docs/authorization-validation/formal/AdmissionSafetyFull.cfg",
    "Docs/authorization-validation/formal/AdmissionSafetyNoPendingProbe.cfg",
    "Docs/authorization-validation/formal/AdmissionSafetyNoGenerationFence.cfg",
    "Docs/authorization-validation/formal/AdmissionSafetyNoExactIdentity.cfg",
    "Docs/authorization-validation/formal/AdmissionSafetyNoHostMediation.cfg",
    "Docs/authorization-validation/formal/README.md",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(spec: dict[str, Any]) -> dict[str, Any]:
    command_id = spec["id"]
    stdout_path = LOGS / f"{command_id}.stdout.log"
    stderr_path = LOGS / f"{command_id}.stderr.log"
    started_at = utc_now()
    monotonic_start_ns = time.monotonic_ns()
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    log_complete = True
    execution_status = "PASS"
    try:
        completed = subprocess.run(
            spec["argv"],
            cwd=RUST,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=1800,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        execution_status = "UNKNOWN"
        log_complete = False
        stdout = error.stdout.decode("utf-8", "replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = error.stderr.decode("utf-8", "replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
    except OSError as error:
        execution_status = "BLOCKED"
        stderr = type(error).__name__
    monotonic_end_ns = time.monotonic_ns()
    ended_at = utc_now()
    stdout_path.write_bytes(stdout.replace("\r\n", "\n").encode("utf-8"))
    stderr_path.write_bytes(stderr.replace("\r\n", "\n").encode("utf-8"))
    expected = spec.get("expected")
    expected_stderr = spec.get("expectedStderr")
    assertion_ok = (expected is None or expected in stdout) and (
        expected_stderr is None or expected_stderr in stderr
    )
    abstract_model_status = None
    if spec.get("assertE5AbstractModel") and execution_status == "PASS":
        try:
            model_report = json.loads(stdout)
            modes = model_report["fullContract"]["modes"]
            assertion_ok = assertion_ok and model_report["fullContract"]["status"] == "PASS"
            assertion_ok = assertion_ok and all(
                mode["explorationComplete"] and mode["violations"] == 0
                for mode in modes.values()
            )
            abstract_model_status = model_report["fullContract"]["status"]
        except (ValueError, KeyError, TypeError):
            assertion_ok = False
            abstract_model_status = "UNKNOWN"
    ignored_count = sum(
        int(match.group(1)) for match in re.finditer(r"(\d+) ignored;", stdout)
    )
    python_tests_run = None
    if spec.get("minimumPythonTests") is not None:
        match = re.search(r"Ran\s+(\d+)\s+tests?\b", stderr)
        python_tests_run = int(match.group(1)) if match else 0
        assertion_ok = assertion_ok and python_tests_run >= int(spec["minimumPythonTests"])
    if execution_status == "PASS" and (exit_code != 0 or not assertion_ok):
        execution_status = "FAIL"
    return {
        "id": command_id,
        "argv": spec["argv"],
        "cwd": str(RUST),
        "startedAt": started_at,
        "endedAt": ended_at,
        "monotonicStartNs": monotonic_start_ns,
        "monotonicEndNs": monotonic_end_ns,
        "timeoutSeconds": 1800,
        "exitCode": exit_code,
        "expectedOutput": expected,
        "expectedStderr": expected_stderr,
        "assertionPassed": assertion_ok,
        "ignoredTests": ignored_count,
        "pythonTestsRun": python_tests_run,
        "abstractModelStatus": abstract_model_status,
        "status": execution_status,
        "stdout": str(stdout_path.relative_to(OUT)).replace("\\", "/"),
        "stderr": str(stderr_path.relative_to(OUT)).replace("\\", "/"),
        "stdoutSha256": sha256(stdout_path),
        "stderrSha256": sha256(stderr_path),
        "logComplete": log_complete,
    }


def tool_version(argv: list[str]) -> str | None:
    try:
        result = subprocess.run(argv, cwd=RUST, text=True, encoding="utf-8", errors="replace", capture_output=True, check=False)
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return (result.stdout or result.stderr).strip()


def runtime_preflight() -> dict[str, Any]:
    tools = {
        "docker": bool(shutil.which("docker")),
        "podman": bool(shutil.which("podman")),
        "wsl": bool(shutil.which("wsl")),
        "mysql": bool(shutil.which("mysql")),
        "redisServer": bool(shutil.which("redis-server")),
        "rabbitmqServer": bool(shutil.which("rabbitmq-server")),
    }
    return {
        "toolsPresent": tools,
        "status": "BLOCKED",
        "reason": "Local readiness does not contact listeners or prove isolated runtime preconditions.",
        "notAttempted": [
            "real signed HTTP PolicyEngine race",
            "real source/delta/outbox commit and publication race",
            "request-side recovery time series",
            "MySQL isolation/primary/UTC runtime capture",
            "Redis/pointer/lease/restart/unknown-ACK fault matrix",
        ],
    }


def write_json(path: Path, value: Any) -> None:
    atomic_json(path, value)


def main(argv: list[str] | None = None) -> int:
    global OUT, LOGS
    parser = argparse.ArgumentParser(description="Freeze an offline-only authorization validation readiness campaign")
    parser.add_argument("--campaign-id", required=True)
    arguments = parser.parse_args(argv)
    campaign_id = arguments.campaign_id
    if not SAFE_CAMPAIGN_ID.fullmatch(campaign_id):
        parser.error("campaign id must match authz-validation-<safe-id>")
    OUT = EVIDENCE_ROOT / campaign_id
    LOGS = OUT / "logs"
    if OUT.exists():
        print("Refusing to overwrite an existing campaign", file=sys.stderr)
        return 2
    missing_sources = [relative for relative in HASHED_SOURCES if not (REPO / relative).is_file()]
    if missing_sources:
        print("Readiness source inventory incomplete: " + ", ".join(missing_sources), file=sys.stderr)
        return 2
    LOGS.mkdir(parents=True)
    started_at = utc_now()
    source_hashes = {relative: sha256(REPO / relative) for relative in HASHED_SOURCES}
    commands: list[dict[str, Any]] = []
    for spec in COMMANDS:
        result = run_command(spec)
        commands.append(result)
        if result["status"] != "PASS" and spec.get("required"):
            break
    completed_ids = {item["id"] for item in commands}
    skipped_commands = [spec["id"] for spec in COMMANDS if spec["id"] not in completed_ids]
    preflight = runtime_preflight()
    ended_at = utc_now()

    required_pass = not skipped_commands and all(item["status"] == "PASS" for item in commands)
    command_status = {item["id"]: item["status"] for item in commands}
    e2_ids = [name for name in command_status if name.startswith("e2-")]
    e2_status = (
        "PASS" if len(e2_ids) == 5 and all(command_status[name] == "PASS" for name in e2_ids)
        else "FAIL" if any(command_status[name] == "FAIL" for name in e2_ids)
        else "SKIP"
    )
    scenarios = {
        "E1-observability-build": (
            "PASS" if all(
                command_status.get(name) == "PASS" for name in (
                    "e1-feature-check", "e1-feature-production-clippy",
                    "e1-policy-engine-feature-tests-build", "e1-astral-db-build",
                )
            ) else "FAIL" if any(
                command_status.get(name) == "FAIL" for name in (
                    "e1-feature-check", "e1-feature-production-clippy",
                    "e1-policy-engine-feature-tests-build", "e1-astral-db-build",
                )
            ) else "SKIP"
        ),
        "E1-production-race": "BLOCKED",
        "E2-pending-probe-omission": command_status.get("e2-pending-probe-omission", "SKIP"),
        "E2-cache-post-recheck-omission": command_status.get("e2-cache-post-recheck-omission", "SKIP"),
        "E2-exact-identity-omission": command_status.get("e2-exact-identity-omission", "SKIP"),
        "E2-final-reload-omission": command_status.get("e2-final-reload-omission", "SKIP"),
        "E2-generation-revoke-fence-omission": command_status.get("e2-generation-revoke-fence-omission", "SKIP"),
        "runtime-suites": (
            "PASS" if all(
                command_status.get(name) == "PASS" for name in (
                    "runtime-policy-engine-lib", "runtime-astral-db-lib",
                    "runtime-astral-common-gateway-contract", "runtime-astral-trustgraph-lib",
                )
            ) else "FAIL" if any(
                command_status.get(name) == "FAIL" for name in (
                    "runtime-policy-engine-lib", "runtime-astral-db-lib",
                    "runtime-astral-common-gateway-contract", "runtime-astral-trustgraph-lib",
                )
            ) else "SKIP"
        ),
        "E3-recovery-tail": "BLOCKED",
        "E4-preconditions-and-faults": "BLOCKED",
        "E5-abstract-bounded-model": command_status.get("e5-bounded-model", "SKIP"),
    }
    manifest = {
        "schemaVersion": 2,
        "campaignId": campaign_id,
        "previousAttempt": PREVIOUS_ATTEMPT,
        "executionClass": "Exec-L2-durable-local-evidence",
        "responsibleAgent": "main-agent",
        "delegated": False,
        "selectionRationale": "Final local gates run against one frozen source snapshot; live scenarios stay blocked.",
        "repositoryRoot": str(REPO),
        "rustWorkspace": str(RUST),
        "startedAt": started_at,
        "endedAt": ended_at,
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "tools": {"cargo": tool_version(["cargo", "--version"]), "rustc": tool_version(["rustc", "--version"])},
        "sourceHashes": source_hashes,
        "commands": commands,
        "skippedCommands": skipped_commands,
        "runtimePreflight": preflight,
        "statisticsUnit": {
            "E2": "one in-memory paired scenario per omission control",
            "E5": "finite abstract-model schedules, not production implementation proof",
            "E1/E3/E4": "not run",
        },
        "secretHandling": "No private node configuration, credentials, or remote targets were read or written.",
    }
    ignored = sum(item["ignoredTests"] for item in commands)
    failed = any(item["status"] == "FAIL" for item in commands)
    unknown = [item["id"] for item in commands if item["status"] == "UNKNOWN"]
    blocked_commands = [item["id"] for item in commands if item["status"] == "BLOCKED"]
    blocked_scenarios = [
        scenario_id for scenario_id, scenario_status in scenarios.items()
        if scenario_status == "BLOCKED"
    ]
    blocked = blocked_commands + blocked_scenarios
    local_status = (
        "PASS" if required_pass else
        "FAIL" if failed else
        "UNKNOWN" if unknown else
        "BLOCKED" if blocked_commands else "SKIP"
    )
    status = {
        "campaignId": campaign_id,
        "overall": "FAIL" if failed else "UNKNOWN" if unknown else "BLOCKED",
        "localReady": local_status,
        "localE2": e2_status,
        "scenarios": scenarios,
        "claims": {"C2": "BLOCKED", "C3": "PLANNED", "C4": "PLANNED", "C6": "BLOCKED", "C7": "BLOCKED"},
        "evidenceBoundary": "Local tests and E5 bounded abstraction do not prove real signed HTTP races, external integration, request-side recovery, or deployment faults.",
        "skips": [
            f"Cargo ignored tests: {ignored}; real integration was not run.",
            "cargo test --workspace runtime suite was not run: some tests start local TCP/HTTP fixtures, outside this preparation boundary.",
            "Workspace exclude crates astral-learn and astral-chat are not covered by workspace gates.",
            *[f"Required local command not executed after earlier gate: {name}" for name in skipped_commands],
        ],
        "unknown": unknown,
        "blocked": blocked,
        "postconditions": {
            "noServicesStarted": True,
            "noExternalSideEffects": True,
            "noProductionDataAccessed": True,
            "noCommitOrPush": True,
            "logsComplete": all(item["logComplete"] for item in commands),
        },
    }
    write_json(OUT / "manifest.json", manifest)
    write_json(OUT / "status.json", status)

    checksum_targets = [OUT / "manifest.json", OUT / "status.json"] + sorted(LOGS.glob("*.log"))
    checksum_path = write_checksums(OUT, checksum_targets)
    verify_checksums(OUT, checksum_path)
    print(json.dumps({"campaignId": campaign_id, "overall": status["overall"], "localReady": status["localReady"]}, ensure_ascii=False))
    return 0 if required_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
