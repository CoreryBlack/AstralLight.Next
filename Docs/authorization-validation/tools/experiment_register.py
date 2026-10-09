#!/usr/bin/env python3
"""Declarative register for the E1--E5 experiment program.

This module is the machine-checkable counterpart of the pre-registered
experiment designs: the stimulus classes of the production-path race, the
E2 omission controls mapped to the model premises, the canary positive
controls, the dependency-fault matrix, the per-request capture
requirements, and the acceptance criteria. The runners consume these
tables; the offline tests lock them, so a scenario, premise mapping, or
acceptance criterion cannot drift silently from the protocol.

Everything here is a declaration of intent and acceptance, NOT an
execution result: no scenario in this register has produced a result by
being declared, and live execution still requires the isolated runtime,
preflight, and durable-postcondition gates of the validation protocol.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

import dependency_profiles as profiles

__all__ = [
    "REGISTER_VERSION",
    "STIMULUS_CLASSES",
    "E2_CONTROL_SCENARIOS",
    "MODEL_ONLY_PREMISES",
    "CANARY_SCENARIOS",
    "DEPENDENCY_PROFILES",
    "PROFILE_SERVICE_DEPENDENCIES",
    "DEPENDENCY_CLASSES_BY_PROFILE",
    "DEPENDENCY_CLASSES",
    "FAULT_TIMINGS",
    "DEPENDENCY_FAULT_MATRIX",
    "DEPENDENCY_FAULT_MATRICES_BY_PROFILE",
    "CAPTURE_REQUIREMENTS",
    "ACCEPTANCE_CRITERIA",
    "validate_register",
]

REGISTER_VERSION = "1.0.0"

# E1: registered revocation-class stimulus forms. The production-path race
# must vary its narrowing stimulus over ALL of these classes so the race is
# not tied to one source form (the diagnostic race covered only
# winning-entry removal and rule-set unbinding).
STIMULUS_CLASSES: Dict[str, Dict[str, Any]] = {
    "rule_set_unbinding": {
        "sourceForm": "RULE_SET unbind",
        "revocationClass": True,
        "note": "advances the fence on all nodes; rebind recovers (S4/I7)",
    },
    "winning_entry_removal": {
        "sourceForm": "RULE_SET entry REMOVE",
        "revocationClass": True,
        "note": "the diagnostic race's stimulus; kept for comparability",
    },
    "direct_rule_removal": {
        "sourceForm": "DIRECT rule REMOVE",
        "revocationClass": True,
        "note": "untested end to end before this register",
    },
    "approval_or_delegation_withdrawal": {
        "sourceForm": "APPROVAL/DELEGATION withdrawal",
        "revocationClass": True,
        "note": "provenance-level narrowing; fan-out per affected card",
    },
    "card_disablement": {
        "sourceForm": "card disablement",
        "revocationClass": True,
        "note": "carrier-level narrowing; must fan out to every scope",
    },
    "aggregate_wide_narrowing": {
        "sourceForm": "aggregate-wide narrowing (card = NULL)",
        "revocationClass": True,
        "note": "enters every affected probe and evidence chain (M1)",
    },
}

# E2: test-only omission controls mapped to the model premises. The
# mapping is locked by the drift-guard tests on the Rust side and by the
# bounded models' premise vocabulary here; host_mediation is model-only
# and has no runtime omission switch (bypass is the model's counterexample
# mechanism, never a production switch).
E2_CONTROL_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "pending_probe": {
        "crate": "astral-db",
        "rustTest": "evidence_cache::tests::e2_pending_probe_omission_accepts_stale_candidate_while_full_contract_reloads",
        "hazard": "source narrowing unpublished while old evidence is accepted",
        "expectedFinding": "counterexample_found",
    },
    "post_recheck": {
        "crate": "astral-db",
        "rustTest": "evidence_cache::tests::e2_post_recheck_omission_accepts_interleaving_while_full_contract_reloads",
        "hazard": "publication interleaving accepted across the two observations",
        "expectedFinding": "counterexample_found",
    },
    "final_reload": {
        "crate": "policy-engine",
        "rustTest": "engine::tests::e2_final_reload_omission_accepts_removed_candidate_while_full_contract_reloads",
        "hazard": "pre-observation fallback admits the removed candidate",
        "expectedFinding": "counterexample_found",
    },
    "exact_identity": {
        "crate": "policy-engine",
        "rustTest": "engine::tests::test_strict_successor_revision_cannot_replace_original_candidate",
        "hazard": "successor revision replaces the original candidate",
        "expectedFinding": "counterexample_found",
    },
    "generation_revoke_fence": {
        "crate": "astral-db",
        "rustTest": "evidence_cache::tests::e2_generation_revoke_fence_omission_accepts_stale_candidate",
        "hazard": "stale generation or pointer rollback accepted",
        "expectedFinding": "counterexample_found",
    },
}

MODEL_ONLY_PREMISES: Tuple[str, ...] = ("host_mediation",)

# E7/E8: canary positive controls. Ground truth is fixed by construction
# (the harness injects the staleness), so a detection rate below one
# falsifies the read-gate contract and invalidates any zero reported by
# the race, availability, or fault experiments.
CANARY_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "suppressed_revocation_delta": {
        "injection": "a revocation-class delta is durably committed but its publication is suppressed",
        "expectedDetectionRate": 1.0,
        "expectedFalseBlockRate": 0.0,
        "note": "the gate must block until the suppressed delta publishes",
    },
    "revision_confused_grant": {
        "injection": "a successor revision is served for the original candidate identity",
        "expectedDetectionRate": 1.0,
        "expectedFalseBlockRate": 0.0,
        "note": "exact identity binding must reject the substitute",
    },
}

# E5/E6: dependency-failure matrix. Each executable deployment profile has
# only the dependency classes present in that profile. Redis remains an
# explicit redis-compat dependency; standalone/distributed Rabbit profiles
# use RabbitMQ while the native single-node profile uses local buses/hub.
DEPENDENCY_PROFILES: Tuple[str, ...] = profiles.PROFILE_IDS
PROFILE_SERVICE_DEPENDENCIES = profiles.SERVICE_DEPENDENCIES_BY_PROFILE
DEPENDENCY_CLASSES_BY_PROFILE = profiles.DEPENDENCY_CLASSES_BY_PROFILE
DEPENDENCY_CLASSES: Tuple[str, ...] = DEPENDENCY_CLASSES_BY_PROFILE[profiles.DEFAULT_PROFILE]
FAULT_TIMINGS: Tuple[str, ...] = profiles.FAULT_TIMINGS
DEPENDENCY_FAULT_MATRICES_BY_PROFILE: Dict[str, Dict[str, Dict[str, Any]]] = {
    profile: profiles.dependency_fault_matrix(profile)
    for profile in DEPENDENCY_PROFILES
}
# Backward-compatible default view; callers needing another deployment must
# select its explicit profile matrix above.
DEPENDENCY_FAULT_MATRIX = DEPENDENCY_FAULT_MATRICES_BY_PROFILE[profiles.DEFAULT_PROFILE]

# Per-experiment capture requirements: the observation fields whose
# absence downgrades the result (E3 without request-side samples keeps
# only a workload-level recovery observation, per the boundary matrix).
CAPTURE_REQUIREMENTS: Dict[str, Tuple[str, ...]] = {
    "E1": (
        "per-request commit/final-observation/stable-check/admission boundaries",
        "cache-or-strict branch",
        "decision reason code",
        "per-mutation hazard attribution (classify_e1_allow_multi)",
        "revocation-class stimulus class id",
    ),
    "E2": (
        "disabled premise id",
        "full-contract control run",
        "expected hazard family",
        "repeatability within the registered repetition budget",
    ),
    "E3": (
        "per-event enqueue/claim/attempt/backoff/parking timestamps",
        "queue-depth time series",
        "target/unrelated/cold-start card decision series",
        "publication drain decomposition",
    ),
    "E4": (
        "per-connection transaction isolation",
        "primary-routing confirmation",
        "UTC/clock-offset observations",
        "cache-generation initialization/rotation events",
        "readiness and liveness recorded separately",
    ),
}

# Acceptance criteria, fixed before execution. Each criterion is a
# machine-checkable predicate over the experiment's recorded output; a
# result that misses its criterion is a falsification, never absorbed
# into the design.
ACCEPTANCE_CRITERIA: Dict[str, Tuple[str, ...]] = {
    "E1": (
        "zero stale ALLOW among strictly-ordered pre-observation samples",
        "every ALLOW carries a complete ordering record",
        "overlap-window outcomes reported separately, never pooled",
        "every registered stimulus class executed",
    ),
    "E2": (
        "each ablated control reproduces its hazard family at least once",
        "the full-contract control yields zero violations under the identical workload",
        "a control that cannot be made to fail weakens its necessity claim and is reported as such",
    ),
    "E3": (
        "zero stale ALLOW throughout the drain",
        "target-card PENDING/DENY separated from unrelated-card availability",
        "drain decomposition reported as distributions",
    ),
    "E4": (
        "every fault window terminates in PENDING/DENY with a reason code",
        "recovery judged at readiness, not liveness",
        "unarchivable preconditions downgrade the claim, never upgrade it",
    ),
    "E7": (
        "canary detection rate one",
        "zero false blocks on fresh evidence",
    ),
    "E8": (
        "bounded tail latency at the registered maximum",
        "zero stale ALLOW and zero errors",
    ),
}


def validate_register() -> Dict[str, Any]:
    """Check the register's internal consistency; return a report dict.

    Locked by the offline tests: the stimulus classes are complete and
    unique, the E2 controls cover every premise that has a runtime switch
    (host_mediation is declared model-only), canary ground truth is fixed
    by construction, the fault matrix is the full cross product, and every
    capture requirement names at least one field.
    """
    problems = []
    if len(STIMULUS_CLASSES) != 6:
        problems.append(f"expected 6 stimulus classes, got {len(STIMULUS_CLASSES)}")
    for key, value in STIMULUS_CLASSES.items():
        if not value.get("revocationClass"):
            problems.append(f"stimulus {key} is not revocation-class")
    premises_with_switch = set(E2_CONTROL_SCENARIOS) | set(MODEL_ONLY_PREMISES)
    if premises_with_switch != {
        "pending_probe", "post_recheck", "final_reload",
        "exact_identity", "generation_revoke_fence", "host_mediation",
    }:
        problems.append("E2 controls + model-only premises do not cover the six premises")
    for premise, spec in E2_CONTROL_SCENARIOS.items():
        if not spec.get("rustTest"):
            problems.append(f"E2 control {premise} has no Rust test id")
        if spec.get("expectedFinding") != "counterexample_found":
            problems.append(f"E2 control {premise} has an unexpected finding")
    for key, spec in CANARY_SCENARIOS.items():
        if spec.get("expectedDetectionRate") != 1.0:
            problems.append(f"canary {key} detection rate is not one")
        if spec.get("expectedFalseBlockRate") != 0.0:
            problems.append(f"canary {key} false-block rate is not zero")
    profile_report = profiles.validate_dependency_profiles()
    if profile_report["status"] != "PASS":
        problems.extend("profile:" + problem for problem in profile_report["problems"])
    for profile in DEPENDENCY_PROFILES:
        profile_dependencies = set(DEPENDENCY_CLASSES_BY_PROFILE[profile])
        expected_profile_pairs = {
            f"{dependency}:{timing}"
            for dependency in profile_dependencies
            for timing in FAULT_TIMINGS
        }
        if set(DEPENDENCY_FAULT_MATRICES_BY_PROFILE[profile]) != expected_profile_pairs:
            problems.append(f"{profile}:dependency fault matrix is not the full cross product")
        for entry in DEPENDENCY_FAULT_MATRICES_BY_PROFILE[profile].values():
            if entry.get("profile") != profile or entry.get("acceptance") != "fail_closed":
                problems.append(f"{profile}:fault matrix metadata is invalid")
    for experiment, fields in CAPTURE_REQUIREMENTS.items():
        if not fields:
            problems.append(f"capture requirements for {experiment} are empty")
    for experiment, criteria in ACCEPTANCE_CRITERIA.items():
        if not criteria:
            problems.append(f"acceptance criteria for {experiment} are empty")
    return {
        "register": "experiment-register",
        "registerVersion": REGISTER_VERSION,
        "status": "PASS" if not problems else "FAIL",
        "problems": problems,
        "counts": {
            "stimulusClasses": len(STIMULUS_CLASSES),
            "e2Controls": len(E2_CONTROL_SCENARIOS),
            "modelOnlyPremises": len(MODEL_ONLY_PREMISES),
            "canaryScenarios": len(CANARY_SCENARIOS),
            "faultMatrixEntries": len(DEPENDENCY_FAULT_MATRIX),
            "profiles": len(DEPENDENCY_PROFILES),
            "profileFaultMatrixEntries": sum(
                len(matrix) for matrix in DEPENDENCY_FAULT_MATRICES_BY_PROFILE.values()
            ),
        },
    }


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys
    report = validate_register()
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["status"] == "PASS" else 1)
