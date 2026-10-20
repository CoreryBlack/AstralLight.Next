#!/usr/bin/env python3
"""Fail-closed validator for distributed authorization scenario reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

SCHEMA_VERSION = 2
POSITIVE_SCENARIOS = {
    "concurrentFirstProjectionRequests",
    "mutationVisibilityAfterRevoke",
    "outOfOrderReadyMessages",
    "ruleSetUnbind",
    "staleLeaseReclaim",
    "alternatingMutations",
    "crashAfterIdempotencyClaim",
    "abacAttributeChange",
    "mutationStorm",
    "concurrentProjectors",
    "decisionEvidenceChain",
}
REQUIRED_INVARIANTS = {f"I{index}" for index in range(1, 10)}
ABLATION_INVARIANTS = {"AB-A", "AB-B", "AB-D"}
FAULT_SCENARIOS = {
    "process-crash": ("processCrashMidRevoke", "I12"),
    "redis-restart": ("redisRestartMidRevoke", "I13"),
}
CS_DISTRIBUTED_SCENARIOS = {
    "cs1RevokeFence", "cs2SourceOracle", "cs3NewGrantGate", "cs4OverlayDeny",
    "cs5Supersession", "cs6RuleSetUnbind", "cs7TargetIsolation", "cs8WriteAlias",
}
CS_DISTRIBUTED_INVARIANTS = {f"CS-{index}" for index in range(1, 9)}


SCENARIO_INVARIANTS = {
    "concurrentFirstProjectionRequests": {"I1"},
    "mutationVisibilityAfterRevoke": {"I2", "I8"},
    "outOfOrderReadyMessages": {"I2"},
    "ruleSetUnbind": {"I7"},
    "staleLeaseReclaim": {"I3"},
    "alternatingMutations": {"I4"},
    "crashAfterIdempotencyClaim": {"I5"},
    "abacAttributeChange": {"I6"},
    "mutationStorm": {"I2", "I4"},
    "concurrentProjectors": {"I1"},
    "decisionEvidenceChain": {"I9"},
}

ABLATION_EXPECTATIONS = {
    "generation-fence": ("AB-A", "ablation-generation-fence"),
    "l1-eviction": ("AB-B", "ablation-l1-refs-eviction"),
    "owner-fence": ("AB-D", "ablation-owner-fence"),
    "ab-c": ("AB-C", "ablation-publisher-confirm-remote"),
}


def failure(message: str) -> dict[str, object]:
    return {"valid": False, "errors": [message]}


def validate(report: dict[str, object], expected_run_id: str | None, mode: str,
             ablation: str | None, expected_owner: str | None,
             expected_replicate: str | None, expected_fault_mode: str | None) -> dict[str, object]:
    errors: list[str] = []
    if report.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"schemaVersion must be {SCHEMA_VERSION}")
    run_id = report.get("runId")
    if not isinstance(run_id, str) or not run_id:
        errors.append("runId is missing")
    if expected_run_id and run_id != expected_run_id:
        errors.append(f"runId mismatch: expected {expected_run_id!r}, got {run_id!r}")
    for field, expected in (("ownerNode", expected_owner), ("replicate", expected_replicate),
                            ("faultMode", expected_fault_mode)):
        if not isinstance(report.get(field), str) or not report.get(field):
            errors.append(f"{field} is missing")
        elif expected is not None and report.get(field) != expected:
            errors.append(f"{field} mismatch: expected {expected!r}, got {report.get(field)!r}")
    if report.get("experimentMode") not in ("positive", "ablation", "fault", "cs-distributed"):
        errors.append("experimentMode must be positive, ablation, fault, or cs-distributed")
    if report.get("allPassed") is not True or report.get("gateStatus") != "PASS":
        errors.append("report gate must declare allPassed=true and gateStatus=PASS")
    expected_nodes = ["node-a", "node-b", "node-c"]
    if report.get("nodeIds") != expected_nodes:
        errors.append(f"nodeIds must equal {expected_nodes}")
    if not isinstance(report.get("expectedScenarioNames"), list):
        errors.append("expectedScenarioNames must be an array")
    identities = report.get("nodeIdentityEvidence")
    if not isinstance(identities, list) or len(identities) != 3:
        errors.append("nodeIdentityEvidence must contain exactly three nodes")
    else:
        identity_nodes = []
        worker_ids = []
        process_hashes = []
        for index, item in enumerate(identities):
            if not isinstance(item, dict):
                errors.append(f"nodeIdentityEvidence[{index}] is not an object")
                continue
            for field in ("nodeId", "workerId", "configFingerprint", "jvmStartTime", "processIdentityHash"):
                value = item.get(field)
                if not isinstance(value, str) or not value or value == "null":
                    errors.append(f"nodeIdentityEvidence[{index}].{field} is required")
            identity_nodes.append(item.get("nodeId"))
            worker_ids.append(item.get("workerId"))
            process_hashes.append(item.get("processIdentityHash"))
        if sorted(value for value in identity_nodes if isinstance(value, str)) != ["node-a", "node-b", "node-c"]:
            errors.append("nodeIdentityEvidence must cover node-a, node-b, and node-c")
        if len(set(worker_ids)) != 3:
            errors.append("nodeIdentityEvidence workerId values must be unique")
        if len(set(process_hashes)) != 3:
            errors.append("nodeIdentityEvidence processIdentityHash values must be unique")
    network_fault = report.get("networkFault")
    if not isinstance(network_fault, dict):
        errors.append("networkFault metadata is required")
    else:
        if network_fault.get("processActuallyCrashed") is not False:
            errors.append("processActuallyCrashed must be false for the current campaign")
        if network_fault.get("networkFaultActuallyInjected") not in (False, True):
            errors.append("networkFaultActuallyInjected must be boolean")
        if network_fault.get("networkFaultActuallyInjected") is True and not network_fault.get("ledgerPath"):
            errors.append("network fault injection requires a ledgerPath")


    invariants = report.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        errors.append("invariants must be a non-empty array")
        invariants = []
    valid_invariants = [item for item in invariants if isinstance(item, dict)]
    if len(valid_invariants) != len(invariants):
        errors.append("invariants contains a non-object entry")
    if any(item.get("passed") is not True for item in valid_invariants):
        errors.append("every invariant must have passed=true")

    if mode == "positive":
        names = report.get("scenarioNames")
        actual_names = set(names) if isinstance(names, list) else set()
        if not isinstance(names, list) or len(names) != len(POSITIVE_SCENARIOS) or len(actual_names) != len(names):
            errors.append("scenarioNames must contain exactly 11 unique entries")
        if actual_names != POSITIVE_SCENARIOS:
            errors.append(f"scenario set mismatch: expected {sorted(POSITIVE_SCENARIOS)}, got {sorted(actual_names)}")
        if report.get("expectedScenarioCount") != len(POSITIVE_SCENARIOS):
            errors.append("expectedScenarioCount must be 11")
        expected_names = report.get("expectedScenarioNames")
        if (not isinstance(expected_names, list)
                or len(expected_names) != len(POSITIVE_SCENARIOS)
                or set(expected_names) != POSITIVE_SCENARIOS
                or len(set(expected_names)) != len(expected_names)):
            errors.append("expectedScenarioNames must match the positive scenario set")
        by_scenario: dict[str, set[str]] = {}
        for item in valid_invariants:
            by_scenario.setdefault(str(item.get("scenario")), set()).add(str(item.get("invariantId")))
        for scenario, expected in SCENARIO_INVARIANTS.items():
            if by_scenario.get(scenario) != expected:
                errors.append(f"invariant mapping mismatch for {scenario}: expected {sorted(expected)}, got {sorted(by_scenario.get(scenario, set()))}")
        covered = {item.get("invariantId") for item in valid_invariants}
        if not REQUIRED_INVARIANTS.issubset(covered):
            errors.append(f"missing invariant coverage: {sorted(REQUIRED_INVARIANTS - covered)}")
        convergences = report.get("convergences")
        if not isinstance(convergences, list) or not convergences:
            errors.append("at least one convergence record is required")
        else:
            matching = [item for item in convergences if isinstance(item, dict)
                        and item.get("scenario") == "mutationVisibilityAfterRevoke"]
            if not matching:
                errors.append("revoke convergence record is missing")
            for item in matching:
                if item.get("allNodesDenyObserved") is not True:
                    errors.append("revoke convergence must observe allNodesDenyObserved=true")
                if not isinstance(item.get("windowMs"), int) or item["windowMs"] < 0:
                    errors.append("convergence windowMs must be a non-negative integer")
        opportunities = report.get("safetyOpportunities")
        matching_opportunities = [item for item in opportunities if isinstance(item, dict)
                                 and item.get("scenario") == "mutationVisibilityAfterRevoke"] \
            if isinstance(opportunities, list) else []
        if len(matching_opportunities) != 1:
            errors.append("exactly one revoke safety opportunity record is required")
        else:
            opportunity = matching_opportunities[0]
            numeric_fields = (
                "revokeIssuedMs", "firstDenyBiasedMs", "unsafeAuthorizationWindowMs",
                "evaluationCount", "allowCount", "pendingCount", "denyCount", "unsafeAllowCount",
            )
            for field in numeric_fields:
                if not isinstance(opportunity.get(field), int) or opportunity[field] < 0:
                    errors.append(f"safety opportunity {field} must be a non-negative integer")
            if all(isinstance(opportunity.get(field), int) for field in numeric_fields):
                if opportunity["unsafeAuthorizationWindowMs"] < 0:
                    errors.append("unsafeAuthorizationWindowMs must be non-negative")
                if opportunity["firstDenyBiasedMs"] < opportunity["revokeIssuedMs"]:
                    errors.append("firstDenyBiasedMs must not precede revokeIssuedMs")
                if opportunity["evaluationCount"] != (
                        opportunity["allowCount"]
                        + opportunity["pendingCount"]
                        + opportunity["denyCount"]):
                    errors.append("safety opportunity counts must sum to evaluationCount")
            if opportunity.get("unsafeAllowCount") != 0:
                errors.append("unsafeAuthorization opportunity must have unsafeAllowCount=0")
        evidence = report.get("evidence")
        if not isinstance(evidence, list) or len(evidence) < 6:
            errors.append("decision evidence must contain at least six rows")
        else:
            for index, item in enumerate(evidence):
                if not isinstance(item, dict):
                    errors.append(f"evidence[{index}] is not an object")
                    continue
                for field in ("requestId", "nodeId", "projectionStatus", "cacheSource", "decision", "reason"):
                    if not item.get(field):
                        errors.append(f"evidence[{index}].{field} is required")
                if item.get("decision") not in ("ALLOW", "DENY"):
                    errors.append(f"evidence[{index}].decision must be ALLOW or DENY")
                for field in ("headGeneration", "projectedGeneration", "revokeFence"):
                    if not isinstance(item.get(field), int):
                        errors.append(f"evidence[{index}].{field} must be an integer")
    elif mode == "ablation":
        expected_mode = ablation
        expectation = ABLATION_EXPECTATIONS.get(expected_mode or "")
        if expectation is None:
            errors.append("ablation validation requires DIST_TEST_ABLATION=generation-fence|l1-eviction|owner-fence")
        else:
            expected_invariant, expected_scenario = expectation
            covered = {item.get("invariantId") for item in valid_invariants}
            actual_scenarios = {item.get("scenario") for item in valid_invariants}
            if covered != {expected_invariant}:
                errors.append(f"ablation invariant mismatch: expected {{{expected_invariant}}}, got {sorted(covered)}")
            if actual_scenarios != {expected_scenario}:
                errors.append(f"ablation scenario mismatch: expected {{{expected_scenario}}}, got {sorted(actual_scenarios)}")
        observations = report.get("failureObservations")
        if not isinstance(observations, list) or not observations:
            errors.append("ablation report must contain failureObservations")
        else:
            for index, item in enumerate(observations):
                if not isinstance(item, dict):
                    errors.append(f"failureObservations[{index}] is not an object")
                    continue
                expected = item.get("expectedFailure")
                observed = item.get("observedFailure")
                if not isinstance(expected, str) or not expected:
                    errors.append(f"failureObservations[{index}].expectedFailure is required")
                if not isinstance(observed, str) or not observed:
                    errors.append(f"failureObservations[{index}].observedFailure is required")
                elif expected != observed:
                    errors.append(f"failureObservations[{index}] expectedFailure != observedFailure")
    elif mode == "fault":
        expectation = FAULT_SCENARIOS.get(expected_fault_mode or "")
        if expectation is None:
            errors.append("fault validation requires fault-mode=process-crash|redis-restart")
        else:
            expected_scenario, expected_invariant = expectation
            actual_names = set(report.get("scenarioNames") or [])
            if actual_names != {expected_scenario}:
                errors.append(f"fault scenario mismatch: expected {{{expected_scenario}}}, got {sorted(actual_names)}")
            covered = {item.get("invariantId") for item in valid_invariants}
            if covered != {expected_invariant}:
                errors.append(f"fault invariant mismatch: expected {{{expected_invariant}}}, got {sorted(covered)}")
            if expected_fault_mode == "process-crash":
                pc = report.get("processCrash")
                if not isinstance(pc, dict):
                    errors.append("processCrash evidence is required")
                else:
                    for field in ("crashedNodeId", "previousWorkerId", "replacementWorkerId"):
                        if not pc.get(field):
                            errors.append(f"processCrash.{field} is required")
                    for field in ("evaluationsDuringDown", "pendingDuringDown",
                                  "denyDuringDown", "allowDuringDown"):
                        if not isinstance(pc.get(field), int) or pc[field] < 0:
                            errors.append(f"processCrash.{field} must be a non-negative integer")
                    if pc.get("processActuallyRestarted") is not True:
                        errors.append("processCrash.processActuallyRestarted must be true")
                    if pc.get("allowDuringDown", 1) != 0:
                        errors.append("processCrash.allowDuringDown must be zero")
            elif expected_fault_mode == "redis-restart":
                rr = report.get("redisRestart")
                if not isinstance(rr, dict):
                    errors.append("redisRestart evidence is required")
                else:
                    for field in ("evaluationsDuringDown", "pendingDuringDown", "denyDuringDown",
                                  "allowDuringDown", "evaluationsAfterRestart",
                                  "pendingAfterRestart", "denyAfterRestart", "allowAfterRestart"):
                        if not isinstance(rr.get(field), int) or rr[field] < 0:
                            errors.append(f"redisRestart.{field} must be a non-negative integer")
                    if rr.get("redisActuallyRestarted") is not True:
                        errors.append("redisRestart.redisActuallyRestarted must be true")
                    if rr.get("allowDuringDown", 1) != 0 or rr.get("allowAfterRestart", 1) != 0:
                        errors.append("redisRestart allow counts must be zero")
    elif mode == "cs-distributed":
        actual_names = set(report.get("scenarioNames") or [])
        if actual_names != CS_DISTRIBUTED_SCENARIOS:
            errors.append(f"cs-distributed scenario mismatch: expected {sorted(CS_DISTRIBUTED_SCENARIOS)}, got {sorted(actual_names)}")
        covered = {item.get("invariantId") for item in valid_invariants}
        if not CS_DISTRIBUTED_INVARIANTS.issubset(covered):
            errors.append(f"missing cs-distributed invariant coverage: {sorted(CS_DISTRIBUTED_INVARIANTS - covered)}")
    else:
        errors.append(f"unsupported mode: {mode}")

    if errors:
        return {"valid": False, "errors": errors, "runId": run_id, "mode": mode}
    return {
        "valid": True,
        "errors": [],
        "runId": run_id,
        "mode": mode,
        "schemaVersion": report.get("schemaVersion"),
        "scenarioCount": len(report.get("scenarioNames", [])),
        "invariantCoverage": sorted({item.get("invariantId") for item in valid_invariants}),
        "reportSha256": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--mode", choices=("positive", "ablation", "fault", "cs-distributed"), default="positive")
    parser.add_argument("--ablation", choices=("generation-fence", "l1-eviction", "owner-fence", "ab-c"))
    parser.add_argument("--fault-mode", choices=("synthetic", "process-crash", "redis-restart"))
    parser.add_argument("--owner")
    parser.add_argument("--replicate")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result: dict[str, object]
    try:
        raw = args.report.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            result = failure("report root must be an object")
        else:
            result = validate(value, args.run_id, args.mode, args.ablation,
                              args.owner, args.replicate, args.fault_mode)
            result["reportSha256"] = digest
    except FileNotFoundError:
        result = failure(f"report does not exist: {args.report}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        result = failure(f"cannot read report: {exc}")

    output = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_text(output, encoding="utf-8")
        os.replace(temporary, args.output)
    else:
        sys.stdout.write(output)
    return 0 if result.get("valid") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
