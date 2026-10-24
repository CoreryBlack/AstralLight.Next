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
        "id": "offline-rust-harness-tests",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "test-harness", "--locked", "--", "--test-threads=1"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "e5-bounded-model",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "test-harness", "--locked", "--lib", "e5_model::tests::full_contract_and_omission_counts_match_the_reference_checker", "--", "--exact", "--test-threads=1"],
        "required": True,
        "expected": "1 passed; 0 failed",
    },
    {
        "id": "offline-tenant-rust-contract",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "test-harness", "--locked", "--lib", "models::tests::", "--", "--test-threads=1"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "e3-reconciliation-rust-contract",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "test-harness", "--locked", "--lib", "e3_reconciliation::tests::", "--", "--test-threads=1"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "e4-protocol-rust-contract",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "test-harness", "--locked", "--lib", "e4_protocol::tests::", "--", "--test-threads=1"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "unbounded-single-rust-contract",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "test-harness", "--locked", "--lib", "unbounded_confirmation::tests::", "--", "--test-threads=1"],
        "required": True,
        "expected": "; 0 failed",
    },
    {
        "id": "workspace-test-compile",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "--workspace", "--no-run"],
        "required": True,
    },
    {
        "id": "e5-bounded-model-two-mutations",
        "argv": ["cargo", "test", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "test-harness", "--locked", "--lib", "two_mutation_model::tests::", "--", "--test-threads=1"],
        "required": True,
        "expected": "; 0 failed",
        "timeoutSeconds": 1800,
    },
    {
        "id": "e5-two-mutation-worker-shards",
        "status": "BLOCKED",
        "required": True,
        "reason": "ProcessPoolExecutor parity, Rust model-derived trace sharding, complete shard result merge and serial/parallel report parity are not implemented; the two-mutation offline model suite is narrower",
    },
    {
        "id": "e5-universal-hypotheses",
        "status": "BLOCKED",
        "required": True,
        "reason": "the Rust U1-U10 evaluator contract is fixture-driven only; complete enumeration and validated aggregate evidence over actual single- and two-mutation runs remain unverified, so the archived Python reference is not dispatched",
    },
]

HASHED_SOURCES = [
    "Cargo.toml",
    "Cargo.lock",
    "test-harness/Cargo.toml",
    "tests-suite/MANIFEST.toml",
    "test-harness/src/lib.rs",
    "test-harness/src/e3_e4_events.rs",
    "test-harness/src/e3_report.rs",
    "test-harness/src/e4_fault_lifecycle.rs",
    "test-harness/src/e4_preconditions.rs",
    "test-harness/src/node_adapter_contract.rs",
    "test-harness/src/readiness_contract.rs",
    "test-harness/src/bounded_execution_contract.rs",
    "test-harness/src/two_mutation_model.rs",
    "test-harness/src/projection_owner_model.rs",
    "test-harness/src/universal_hypotheses.rs",
    "test-harness/src/campaign.rs",
    "test-harness/src/acceptance.rs",
    "test-harness/src/evaluate_acceptance.rs",
    "test-harness/src/model_acceptance.rs",
    "test-harness/src/e1_log.rs",
    "test-harness/src/e1_validation.rs",
    "test-harness/src/e3_reconciliation.rs",
    "test-harness/src/e4_protocol.rs",
    "test-harness/src/e5_model.rs",
    "test-harness/src/e5_model/report.rs",
    "test-harness/src/models.rs",
    "test-harness/src/unbounded_confirmation.rs",
    "test-harness/src/dependency_profiles.rs",
    "test-harness/src/experiment_register.rs",
    "test-harness/src/lifecycle.rs",
    "test-harness/src/bin/e5-model-check.rs",
    "test-harness/src/bin/test-campaign.rs",
    "test-harness/src/fixtures/e5-single-reference-28.json",
    "policy-engine/Cargo.toml",
    "policy-engine/src/e1_observation.rs",
    "policy-engine/src/engine.rs",
    "policy-engine/src/hit_stats.rs",
    "policy-engine/src/lib.rs",
    "astral-db/Cargo.toml",
    "astral-db/src/authorization_projection_repository.rs",
    "astral-db/src/evidence_cache.rs",
    "astral-db/src/permission_query.rs",
    "tests-suite/series/RQ3/authorization_projection_integration.rs",
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
    "Docs/规范/Rust后端编码规范_V1.0.md",
    "astral-common/Cargo.toml",
    "astral-common/src/audit.rs",
    "astral-common/src/experiment_observation.rs",
    "astral-common/src/lib.rs",
    "astral-common/src/middleware/permission_check_shared.rs",
    "astral-db/src/cache_epoch.rs",
    "astral-db/src/grant_repository.rs",
    "astral-db/src/lib.rs",
    "Docs/authorization-validation/tools/experiment_common.py",
    "Docs/authorization-validation/tools/e3_e4.py",
    "Docs/authorization-validation/tools/node_adapter.py",
    "Docs/authorization-validation/tools/e1_runner.py",
    "Docs/authorization-validation/tools/lifecycle_reducer.py",
    "Docs/authorization-validation/tools/e3_runner.py",
    "Docs/authorization-validation/tools/e4_fault_driver.py",
    "Docs/authorization-validation/tools/e5_model_check.py",
    "Docs/authorization-validation/tools/e5_model_check_two_mutations.py",
    "Docs/authorization-validation/tools/universal_hypotheses_check.py",
    "Docs/authorization-validation/tools/experiment_register.py",
    "Docs/authorization-validation/tools/run_single_node_campaign.py",
    "Docs/authorization-validation/tools/model_acceptance.py",
    "Docs/authorization-validation/tools/README_READONLY_PROBES.md",
    "Docs/authorization-validation/archive/python-tests/README.md",
    "Docs/authorization-validation/archive/python-tests/test_bounded_model_execution.py",
    "Docs/authorization-validation/archive/python-tests/test_classify_e1_properties.py",
    "Docs/authorization-validation/archive/python-tests/test_dependency_profiles.py",
    "Docs/authorization-validation/archive/python-tests/test_e1_runner.py",
    "Docs/authorization-validation/archive/python-tests/test_e3_e4.py",
    "Docs/authorization-validation/archive/python-tests/test_e3_runner.py",
    "Docs/authorization-validation/archive/python-tests/test_e4_fault_driver.py",
    "Docs/authorization-validation/archive/python-tests/test_e5_model_check.py",
    "Docs/authorization-validation/archive/python-tests/test_e5_model_check_two_mutations.py",
    "Docs/authorization-validation/archive/python-tests/test_experiment_common.py",
    "Docs/authorization-validation/archive/python-tests/test_experiment_register.py",
    "Docs/authorization-validation/archive/python-tests/test_lifecycle_reducer.py",
    "Docs/authorization-validation/archive/python-tests/test_model_acceptance.py",
    "Docs/authorization-validation/archive/python-tests/test_node_adapter.py",
    "Docs/authorization-validation/archive/python-tests/test_projection_owner_model.py",
    "Docs/authorization-validation/archive/python-tests/test_run_single_node_campaign.py",
    "Docs/authorization-validation/archive/python-tests/test_tenant_isolation_model.py",
    "Docs/authorization-validation/archive/python-tests/test_unbounded_confirmation.py",
    "Docs/authorization-validation/archive/python-tests/test_universal_hypotheses_check.py",
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


def source_snapshot() -> dict[str, str | None]:
    snapshot: dict[str, str | None] = {}
    for relative in HASHED_SOURCES:
        try:
            snapshot[relative] = sha256(REPO / relative)
        except OSError:
            snapshot[relative] = None
    return snapshot


def run_command(spec: dict[str, Any]) -> dict[str, Any]:
    command_id = spec["id"]
    stdout_path = LOGS / f"{command_id}.stdout.log"
    stderr_path = LOGS / f"{command_id}.stderr.log"
    started_at = utc_now()
    monotonic_start_ns = time.monotonic_ns()
    timeout_seconds = int(spec.get("timeoutSeconds", 1800))
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
            timeout=timeout_seconds,
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
    ignored_count = sum(
        int(match.group(1)) for match in re.finditer(r"(\d+) ignored;", stdout)
    )

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
        "timeoutSeconds": timeout_seconds,
        "exitCode": exit_code,
        "expectedOutput": expected,
        "expectedStderr": expected_stderr,
        "assertionPassed": assertion_ok,
        "ignoredTests": ignored_count,
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


def aggregate_status(statuses: dict[str, str], required: tuple[str, ...]) -> str:
    observed = [statuses.get(command_id, "SKIP") for command_id in required]
    for status in ("FAIL", "UNKNOWN", "BLOCKED", "PENDING"):
        if status in observed:
            return status
    if any(status != "PASS" for status in observed):
        return "SKIP"
    return "PASS"


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
    source_hashes = source_snapshot()
    commands: list[dict[str, Any]] = []
    source_drift: list[str] = []
    for spec in COMMANDS:
        if spec.get("status") == "BLOCKED":
            commands.append(
                {
                    "id": spec["id"],
                    "argv": [],
                    "cwd": str(RUST),
                    "startedAt": None,
                    "endedAt": None,
                    "exitCode": None,
                    "assertionPassed": False,
                    "status": "BLOCKED",
                    "reason": spec["reason"],
                    "logComplete": True,
                }
            )
            continue
        result = run_command(spec)
        commands.append(result)
        last_executed = result
        current_hashes = source_snapshot()
        changed = [
            relative for relative, digest in source_hashes.items()
            if current_hashes.get(relative) != digest
        ]
        if changed:
            source_drift = changed
            for completed in commands:
                if completed["status"] == "PASS":
                    completed["status"] = "UNKNOWN"
                    completed["assertionPassed"] = False
                    completed["sourceDrift"] = changed
                    completed["reason"] = "source snapshot changed during readiness execution"
            break
        if result["status"] != "PASS" and spec.get("required"):
            break
    completed_ids = {item["id"] for item in commands}
    skipped_commands = [spec["id"] for spec in COMMANDS if spec["id"] not in completed_ids]
    preflight = runtime_preflight()
    ended_at = utc_now()
    final_source_hashes = source_snapshot()
    source_drift.extend(
        relative for relative, digest in source_hashes.items()
        if final_source_hashes.get(relative) != digest and relative not in source_drift
    )
    if source_drift:
        for result in commands:
            if result["status"] == "PASS":
                result["status"] = "UNKNOWN"
                result["assertionPassed"] = False
                result["sourceDrift"] = source_drift
                result["reason"] = "source snapshot changed before final readiness freeze"
    required_pass = not source_drift and not skipped_commands and all(item["status"] == "PASS" for item in commands)
    command_status = {item["id"]: item["status"] for item in commands}
    e2_ids = [name for name in command_status if name.startswith("e2-")]
    e2_status = (
        "PASS" if len(e2_ids) == 5 and all(command_status[name] == "PASS" for name in e2_ids)
        else "FAIL" if any(command_status[name] == "FAIL" for name in e2_ids)
        else "UNKNOWN" if any(command_status[name] == "UNKNOWN" for name in e2_ids)
        else "BLOCKED" if any(command_status[name] == "BLOCKED" for name in e2_ids)
        else "SKIP"
    )
    scenarios = {
        "E1-observability-build": aggregate_status(command_status, (
            "e1-feature-check", "e1-feature-production-clippy",
            "e1-policy-engine-feature-tests-build", "e1-astral-db-build",
        )),
        "E1-production-race": "BLOCKED",
        "E2-pending-probe-omission": command_status.get("e2-pending-probe-omission", "SKIP"),
        "E2-cache-post-recheck-omission": command_status.get("e2-cache-post-recheck-omission", "SKIP"),
        "E2-exact-identity-omission": command_status.get("e2-exact-identity-omission", "SKIP"),
        "E2-final-reload-omission": command_status.get("e2-final-reload-omission", "SKIP"),
        "E2-generation-revoke-fence-omission": command_status.get("e2-generation-revoke-fence-omission", "SKIP"),
        "runtime-suites": aggregate_status(command_status, (
            "runtime-policy-engine-lib", "runtime-astral-db-lib",
            "runtime-astral-common-gateway-contract", "runtime-astral-trustgraph-lib",
        )),
        "E3-recovery-tail": "BLOCKED",
        "E4-preconditions-and-faults": "BLOCKED",
        "E5-abstract-bounded-model": command_status.get("e5-bounded-model", "SKIP"),
        "E5-abstract-bounded-model-two-mutations": command_status.get(
            "e5-bounded-model-two-mutations", "BLOCKED"
        ),
        "E5-universal-hypotheses": command_status.get(
            "e5-universal-hypotheses", "BLOCKED"
        ),
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
        "finalSourceHashes": final_source_hashes,
        "sourceDrift": source_drift,
        "commands": commands,
        "skippedCommands": skipped_commands,
        "runtimePreflight": preflight,
        "statisticsUnit": {
            "E2": "one in-memory paired scenario per omission control; five one-shot controls, no repeated-run distribution",
            "E5": "This readiness command runs the single- and two-mutation abstract Rust model targets; U1-U10 evaluator fixtures are registered separately, while full two-model universal enumeration and worker/shard parity remain BLOCKED and are not dispatched",
            "E1/E3/E4": "not run",
        },
        "coverage": {
            "E2": {
                "scope": "five exact Rust unit-test omission controls",
                "runsPerControl": 1,
                "repeatedRunProof": False,
                "productionBinaryProof": False,
                "hostMediationProof": False,
                "status": e2_status,
            }
        },
        "secretHandling": "No private node configuration, credentials, or remote targets were read or written.",
    }
    ignored = sum(item["ignoredTests"] for item in commands)
    failed = any(item["status"] == "FAIL" for item in commands)
    unknown = [item["id"] for item in commands if item["status"] == "UNKNOWN"]
    if source_drift:
        unknown.append("source-drift")
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
        "localE2": "UNKNOWN" if source_drift and e2_ids else e2_status,
        "localSourceSnapshot": "UNKNOWN" if source_drift else "PASS",
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
        "sourceDrift": source_drift,
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
