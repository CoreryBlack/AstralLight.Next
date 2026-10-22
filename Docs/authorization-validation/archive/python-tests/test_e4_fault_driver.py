#!/usr/bin/env python3
"""Offline unit tests for tools/e4_fault_driver.py.

Every test uses fully fake in-memory controllers. No database, Redis, HTTP
service, network, filesystem, or subprocess resource is touched; the driver
itself has no I/O capability. The suite verifies:

- structural authorization validation and precondition blocking (BLOCKED
  before any controller contact: live-gate tripwire, unknown fault ids,
  invalid authorization, capability/preflight failures),
- the happy path for all six frozen fault cases (PASS requires proven
  restoration, reconciliation, postcondition, host admission != ALLOW, and
  the e3_e4.evaluate_fault_outcomes cross-check),
- fail-closed outcome classification (ALLOW anywhere is FAIL; UNKNOWN and
  missing fields are never PASS),
- per-case source audit / generation / durable-reconcile proof requirements,
- UNKNOWN mapping on timeouts/disconnects with the recovery path still run,
- partial-failure restore handling and postcondition violations,
- the bounded one-attempt rule (no retry, no automatic replay; retries stay
  forbidden until durable reconciliation is proven),
- stable operation ids and the absence of authorization token values in any
  returned record,
- the offline plan/CLI surface (PLANNED cases, BLOCKED live integration, no
  execution flag exists at all).
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import e3_e4  # noqa: E402
import e4_fault_driver  # noqa: E402
import experiment_common  # noqa: E402
from e4_fault_driver import (  # noqa: E402
    CASE_SPECS,
    ControllerDisconnect,
    ControllerTimeout,
    FAULT_CASES as NATIVE_FAULT_CASES,
    FAULT_CASES_LEGACY_COMPAT,
    MAX_ATTEMPTS,
    build_fault_plan,
    run_fault_case as _run_fault_case,
    run_fault_matrix as _run_fault_matrix,
    validate_authorization as _validate_authorization,
)

LEGACY_PROFILE = "redis-compat"
FAULT_CASES = FAULT_CASES_LEGACY_COMPAT
RUN_ID = "authz-validation-e4demo"
ISOLATE_TOKEN = "isolate-authz-validation-e4demo-run-a1"
APPROVAL_TOKEN = "approve-authz-validation-e4demo-run-b2"


def run_fault_case(controller: Any, authorization: Any, fault_id: Any, **kwargs: Any) -> Dict[str, Any]:
    kwargs.setdefault("profile", LEGACY_PROFILE)
    return _run_fault_case(controller, authorization, fault_id, **kwargs)


def run_fault_matrix(controller: Any, authorization: Any, **kwargs: Any) -> Dict[str, Any]:
    kwargs.setdefault("profile", LEGACY_PROFILE)
    return _run_fault_matrix(controller, authorization, **kwargs)


def validate_authorization(authorization: Any, fault_id: Optional[str] = None, **kwargs: Any) -> List[str]:
    kwargs.setdefault("profile", LEGACY_PROFILE)
    return _validate_authorization(authorization, fault_id, **kwargs)


DEFAULT_OBSERVATION: Dict[str, Any] = {
    "observed": "PENDING",
    "reason": "AUTHORIZATION_PENDING",
    "host_admission": "PENDING",
    "evidence_generation": "epoch-20260919",
    "audit_ref": "audit-op-1",
}


def make_authorization(fault_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "exec_level": "Exec-L3",
        "isolate_token": ISOLATE_TOKEN,
        "approval_token": APPROVAL_TOKEN,
        "allowlist": list(FAULT_CASES) if fault_ids is None else list(fault_ids),
        "approved_by": "user-approval-record",
    }


class FakeController:
    """Scripted in-memory controller; records every hook invocation.

    ``script`` maps hook names to either an exception instance (raised), a
    callable (called with the context), or a static mapping (returned as a
    copy). Hooks without a script entry use safe passing defaults, so a
    default-constructed FakeController drives the full happy path.
    """

    def __init__(
        self,
        *,
        supported: Optional[List[str]] = None,
        script: Optional[Dict[str, Any]] = None,
        require_token_scope: bool = True,
    ) -> None:
        self.calls: List[Tuple[str, Optional[str]]] = []
        self.contexts: List[Tuple[str, Dict[str, Any]]] = []
        self.supported = list(FAULT_CASES) if supported is None else list(supported)
        self.script = dict(script or {})
        self.require_token_scope = require_token_scope

    # -- plumbing -----------------------------------------------------------
    def _execute(self, name: str, context: Optional[Dict[str, Any]], default: Callable[[], Dict[str, Any]]) -> Any:
        self.calls.append((name, None if context is None else context.get("operation_id")))
        if context is not None:
            self.contexts.append((name, dict(context)))
        action = self.script.get(name)
        if action is None:
            return default()
        if isinstance(action, Exception):
            raise action
        if callable(action):
            return action(context)
        if isinstance(action, dict):
            return dict(action)
        # Static non-mapping values pass through unchanged so tests can
        # exercise the driver's non-mapping-response handling.
        return action

    def call_count(self, name: str) -> int:
        return sum(1 for call in self.calls if call[0] == name)

    def _authorized(self, context: Optional[Dict[str, Any]]) -> bool:
        if not self.require_token_scope or context is None:
            return True
        authorization = context.get("authorization") or {}
        run_id = str(authorization.get("run_id", ""))
        isolate = str(authorization.get("isolate_token", ""))
        approval = str(authorization.get("approval_token", ""))
        return bool(run_id) and run_id in isolate and run_id in approval

    # -- FaultController contract --------------------------------------------
    def capabilities(self) -> Dict[str, Any]:
        return self._execute(
            "capabilities",
            None,
            lambda: {
                "controller_id": "fake-controller",
                "supported_faults": self.supported,
                "isolation": "isolate-" + RUN_ID,
                "read_only_preflight": True,
            },
        )

    def preflight(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(
            "preflight",
            context,
            lambda: {"ok": True, "authorization_ok": self._authorized(context), "checks": {"fake": "pass"}},
        )

    def prepare(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(
            "prepare", context, lambda: {"prepared": True, "prepare_ref": "fake-prepare-ref"}
        )

    def apply(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(
            "apply", context, lambda: {"applied": True, "apply_ref": "fake-apply-ref"}
        )

    def observe(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute("observe", context, lambda: dict(DEFAULT_OBSERVATION))

    def restore(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(
            "restore", context, lambda: {"restored": True, "restore_ref": "fake-restore-ref"}
        )

    def reconcile(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(
            "reconcile",
            context,
            lambda: {"reconciled": True, "proof_ref": "fake-reconcile-proof", "durable_proof": True},
        )

    def verify_postcondition(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(
            "verify_postcondition", context, lambda: {"ok": True, "checks": {"fake": "pass"}}
        )


def run_ok(controller: FakeController, fault_id: str, **kwargs: Any) -> Dict[str, Any]:
    kwargs.setdefault("allow_live_execution", True)
    return run_fault_case(controller, make_authorization(), fault_id, **kwargs)


class AuthorizationTests(unittest.TestCase):
    """Structural authorization validation blocks before controller contact."""

    def _blocked(self, authorization: Any, fault_id: str = "redis_unavailable") -> Dict[str, Any]:
        controller = FakeController()
        result = run_fault_case(controller, authorization, fault_id, allow_live_execution=True)
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(controller.calls, [], "controller must not be contacted on invalid authorization")
        return result

    def test_missing_authorization_blocked(self) -> None:
        result = self._blocked(None)
        self.assertEqual(result["stages"]["authorization"]["detail"], "authorization_not_a_mapping")

    def test_invalid_run_id_blocked(self) -> None:
        authorization = make_authorization()
        authorization["run_id"] = "bad run id!"
        result = self._blocked(authorization)
        self.assertIn("invalid:run_id", result["stages"]["authorization"]["detail"])

    def test_exec_level_must_be_l3(self) -> None:
        authorization = make_authorization()
        authorization["exec_level"] = "Exec-L1"
        result = self._blocked(authorization)
        self.assertIn("invalid:exec_level", result["stages"]["authorization"]["detail"])

    def test_missing_isolate_token_blocked(self) -> None:
        authorization = make_authorization()
        del authorization["isolate_token"]
        result = self._blocked(authorization)
        self.assertIn("invalid:isolate_token", result["stages"]["authorization"]["detail"])

    def test_token_not_run_scoped_blocked(self) -> None:
        authorization = make_authorization()
        authorization["approval_token"] = "approve-some-other-run-xyz"
        result = self._blocked(authorization)
        self.assertIn("not_run_scoped:approval_token", result["stages"]["authorization"]["detail"])

    def test_identical_tokens_blocked(self) -> None:
        authorization = make_authorization()
        authorization["isolate_token"] = ISOLATE_TOKEN
        authorization["approval_token"] = ISOLATE_TOKEN
        result = self._blocked(authorization)
        self.assertIn("tokens_not_distinct", result["stages"]["authorization"]["detail"])

    def test_missing_approval_token_blocked(self) -> None:
        authorization = make_authorization()
        del authorization["approval_token"]
        self._blocked(authorization)

    def test_missing_approved_by_blocked(self) -> None:
        authorization = make_authorization()
        authorization["approved_by"] = ""
        self._blocked(authorization)

    def test_empty_allowlist_blocked(self) -> None:
        authorization = make_authorization(fault_ids=[])
        self._blocked(authorization)

    def test_fault_not_in_allowlist_blocked(self) -> None:
        authorization = make_authorization(fault_ids=["redis_unavailable"])
        controller = FakeController()
        result = run_fault_case(controller, authorization, "stale_hmac", allow_live_execution=True)
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertIn("fault_not_in_allowlist", result["stages"]["authorization"]["detail"])
        self.assertEqual(controller.calls, [])

    def test_unknown_fault_id_refused(self) -> None:
        controller = FakeController()
        result = run_fault_case(controller, make_authorization(), "disk_full", allow_live_execution=True)
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["validation"]["detail"], "unknown_fault_id")
        self.assertEqual(controller.calls, [])

    def test_validation_helper_reports_all_problems(self) -> None:
        problems = validate_authorization({"run_id": "!!", "exec_level": "nope"})
        self.assertIn("invalid:run_id", problems)
        self.assertIn("invalid:exec_level", problems)
        self.assertIn("invalid:allowlist", problems)
        self.assertIn("invalid:approved_by", problems)

    def test_valid_authorization_has_no_problems(self) -> None:
        self.assertEqual(validate_authorization(make_authorization()), [])


class PreconditionBlockingTests(unittest.TestCase):
    """Capability and preflight failures BLOCK before any mutation."""

    def test_no_controller_blocked(self) -> None:
        result = run_fault_case(None, make_authorization(), "redis_unavailable", allow_live_execution=True)
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["controller"]["detail"], "no_controller_injected")

    def test_controller_missing_capability_hook_blocked(self) -> None:
        class Bare:
            pass

        controller = Bare()
        result = run_fault_case(controller, make_authorization(), "redis_unavailable", allow_live_execution=True)
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertIn("controller_hook_missing", result["stages"]["capabilities"]["detail"])

    def test_unsupported_fault_blocked_before_prepare(self) -> None:
        controller = FakeController(supported=["redis_unavailable"])
        result = run_ok(controller, "pointer_movement")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["capabilities"]["detail"], "fault_not_supported_by_controller")
        self.assertEqual(controller.call_count("prepare"), 0)
        self.assertEqual(controller.call_count("apply"), 0)

    def test_read_only_preflight_not_declared_blocked(self) -> None:
        controller = FakeController(
            script={"capabilities": {"controller_id": "c", "supported_faults": list(FAULT_CASES)}}
        )
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(
            result["stages"]["capabilities"]["detail"],
            "controller_does_not_declare_read_only_preflight",
        )

    def test_isolation_declaration_must_be_run_scoped(self) -> None:
        for isolation in (None, "", "run-scoped-fake", "isolate-some-other-run"):
            with self.subTest(isolation=isolation):
                controller = FakeController(
                    script={
                        "capabilities": {
                            "controller_id": "c",
                            "supported_faults": list(FAULT_CASES),
                            "isolation": isolation,
                            "read_only_preflight": True,
                        }
                    }
                )
                result = run_ok(controller, "redis_unavailable")
                self.assertEqual(result["overall"], "BLOCKED")
                self.assertEqual(
                    result["stages"]["capabilities"]["detail"],
                    "controller_isolation_not_run_scoped",
                )
                self.assertEqual(controller.call_count("prepare"), 0)

    def test_preflight_not_ok_blocked(self) -> None:
        controller = FakeController(script={"preflight": {"ok": False, "authorization_ok": True}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["preflight"]["detail"], "preflight_failed")
        self.assertEqual(controller.call_count("prepare"), 0)

    def test_controller_rejecting_authorization_tokens_blocked(self) -> None:
        controller = FakeController(script={"preflight": {"ok": True, "authorization_ok": False}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["preflight"]["detail"], "controller_rejected_authorization")
        self.assertEqual(controller.call_count("prepare"), 0)

    def test_preflight_exception_blocked(self) -> None:
        controller = FakeController(script={"preflight": RuntimeError("boom")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(controller.call_count("prepare"), 0)

    def test_preflight_non_mapping_blocked(self) -> None:
        controller = FakeController(script={"preflight": "not-a-mapping"})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["preflight"]["detail"], "controller_returned_non_mapping")


class PrepareGateTests(unittest.TestCase):
    """Durable prepare proof is required before apply."""

    def test_prepare_refusal_blocked_without_recovery_calls(self) -> None:
        controller = FakeController(script={"prepare": {"prepared": False}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["prepare"]["detail"], "prepare_refused_by_controller")
        self.assertEqual(controller.call_count("apply"), 0)
        self.assertEqual(controller.call_count("restore"), 0)
        self.assertEqual(controller.call_count("reconcile"), 0)

    def test_prepare_without_durable_ref_unknown(self) -> None:
        controller = FakeController(script={"prepare": {"prepared": True}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["prepare"]["detail"], "prepare_durable_ref_missing")
        self.assertEqual(controller.call_count("apply"), 0, "apply must never run on an unproven prepare")
        self.assertEqual(controller.call_count("restore"), 1, "recovery still runs after unknown prepare")
        self.assertEqual(controller.call_count("reconcile"), 1)

    def test_prepare_timeout_unknown_and_apply_skipped(self) -> None:
        controller = FakeController(script={"prepare": ControllerTimeout("slow")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["prepare"]["detail"], "controller_timeout")
        self.assertEqual(result["stages"]["apply"], {"status": "SKIP", "detail": "prepare_unproven_apply_skipped"})
        self.assertEqual(controller.call_count("apply"), 0)
        self.assertEqual(controller.call_count("restore"), 1)
        self.assertEqual(controller.call_count("reconcile"), 1)
        self.assertEqual(controller.call_count("verify_postcondition"), 1)


class HappyPathTests(unittest.TestCase):
    """All six frozen cases pass end-to-end with a passing fake controller."""

    def test_each_fault_case_passes(self) -> None:
        for fault_id in FAULT_CASES:
            with self.subTest(fault_id=fault_id):
                controller = FakeController()
                result = run_ok(controller, fault_id)
                self.assertEqual(result["overall"], "PASS")
                self.assertEqual(result["observed"], "PENDING")
                self.assertTrue(result["reason"])
                self.assertEqual(result["host_admission"], "PENDING")
                self.assertTrue(result["restoration_proven"])
                self.assertTrue(result["reconciliation_proven"])
                self.assertTrue(result["postcondition_proven"])
                self.assertTrue(result["retry_permitted"])
                self.assertEqual(result["attempt"], 1)
                self.assertEqual(result["retries"], 0)
                self.assertEqual(result["max_attempts"], MAX_ATTEMPTS)
                self.assertEqual(result["stages"]["cross_check"]["status"], "PASS")
                self.assertEqual(
                    result["stages"]["cross_check"]["validator_kind"],
                    e3_e4.evaluate_fault_outcomes([])["kind"],
                )
                # Every hook ran exactly once (one attempt, no replay).
                for hook in (
                    "capabilities",
                    "preflight",
                    "prepare",
                    "apply",
                    "observe",
                    "restore",
                    "reconcile",
                    "verify_postcondition",
                ):
                    self.assertEqual(controller.call_count(hook), 1, hook)

    def test_matrix_all_six_passes_and_is_complete(self) -> None:
        controller = FakeController()
        result = run_fault_matrix(controller, make_authorization(), allow_live_execution=True)
        self.assertEqual(result["overall"], "PASS")
        self.assertTrue(result["matrix_complete"])
        self.assertEqual(len(result["faults"]), 6)
        self.assertEqual([fault["fault_id"] for fault in result["faults"]], list(FAULT_CASES))

    def test_matrix_subset_is_not_complete(self) -> None:
        controller = FakeController()
        result = run_fault_matrix(
            controller,
            make_authorization(fault_ids=["redis_unavailable"]),
            fault_ids=["redis_unavailable"],
            allow_live_execution=True,
        )
        self.assertEqual(result["overall"], "PASS")
        self.assertFalse(result["matrix_complete"])
        self.assertEqual(len(result["missing_faults"]), 5)

    def test_operation_ids_stable_and_distinct(self) -> None:
        controller = FakeController()
        result = run_fault_matrix(controller, make_authorization(), allow_live_execution=True)
        operation_ids = [fault["operation_id"] for fault in result["faults"]]
        self.assertEqual(len(set(operation_ids)), 6)
        for fault_id, operation_id in zip(FAULT_CASES, operation_ids):
            self.assertEqual(
                operation_id,
                experiment_common.stable_id(RUN_ID, "e4-fault:" + fault_id + ":attempt-1"),
            )

    def test_controller_receives_context_and_authorization(self) -> None:
        controller = FakeController()
        run_ok(controller, "redis_unavailable")
        context_by_name = {name: ctx for name, ctx in controller.contexts}
        self.assertIn("apply", context_by_name)
        apply_context = context_by_name["apply"]
        self.assertEqual(apply_context["run_id"], RUN_ID)
        self.assertEqual(apply_context["stage"], "apply")
        self.assertEqual(apply_context["attempt"], 1)
        self.assertIn("operation_id", apply_context)
        # The controller (fake) receives the tokens so it can verify them.
        self.assertEqual(apply_context["authorization"]["run_id"], RUN_ID)

    def test_input_authorization_not_mutated(self) -> None:
        authorization = make_authorization()
        snapshot = copy.deepcopy(authorization)
        controller = FakeController()
        run_fault_case(controller, authorization, "redis_unavailable", allow_live_execution=True)
        self.assertEqual(authorization, snapshot)


class FailClosedOutcomeTests(unittest.TestCase):
    """ALLOW anywhere is FAIL; UNKNOWN and missing fields are never PASS."""

    def test_observed_allow_is_fail(self) -> None:
        controller = FakeController(script={"observe": dict(DEFAULT_OBSERVATION, observed="ALLOW")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "FAIL")
        self.assertEqual(result["stages"]["observe"]["detail"], "allow_observed_fail_closed_violation")
        self.assertEqual(result["stages"]["cross_check"]["status"], "FAIL")
        self.assertIn("allow_observed_fail_closed_violation", json.dumps(result["stages"]["cross_check"]))

    def test_host_admission_allow_is_fail_even_when_decision_denies(self) -> None:
        controller = FakeController(script={"observe": dict(DEFAULT_OBSERVATION, observed="DENY", host_admission="ALLOW")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "FAIL")
        self.assertEqual(result["stages"]["observe"]["detail"], "host_admission_allow_violation")

    def test_observed_unknown_is_unknown(self) -> None:
        controller = FakeController(script={"observe": dict(DEFAULT_OBSERVATION, observed="UNKNOWN")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["cross_check"]["status"], "UNKNOWN")

    def test_missing_observed_is_blocked_never_pass(self) -> None:
        controller = FakeController(script={"observe": {"reason": "X", "host_admission": "PENDING"}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["observe"]["detail"], "missing:observed")
        self.assertEqual(result["stages"]["cross_check"]["status"], "SKIP")

    def test_missing_reason_code_is_blocked_never_pass(self) -> None:
        controller = FakeController(script={"observe": dict(DEFAULT_OBSERVATION, reason="   ")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["observe"]["detail"], "missing:reason_code")
        self.assertEqual(result["stages"]["cross_check"]["status"], "BLOCKED")

    def test_missing_host_admission_is_unknown_never_pass(self) -> None:
        observation = {key: value for key, value in DEFAULT_OBSERVATION.items() if key != "host_admission"}
        controller = FakeController(script={"observe": observation})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["observe"]["detail"], "host_admission_not_observed")

    def test_host_admission_unknown_is_unknown(self) -> None:
        controller = FakeController(script={"observe": dict(DEFAULT_OBSERVATION, host_admission="UNKNOWN")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")

    def test_unrecognized_observed_value_blocked(self) -> None:
        controller = FakeController(script={"observe": dict(DEFAULT_OBSERVATION, observed="MAYBE")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["observe"]["detail"], "unrecognized_observed_value")


class EvidenceRequirementTests(unittest.TestCase):
    """Per-case source audit / generation / durable-proof evidence."""

    def test_pointer_movement_requires_generation_evidence(self) -> None:
        observation = {key: value for key, value in DEFAULT_OBSERVATION.items() if key != "evidence_generation"}
        controller = FakeController(script={"observe": observation})
        result = run_ok(controller, "pointer_movement")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertIn(
            "missing_evidence:evidence_generation",
            result["stages"]["evidence"]["detail"],
        )
        # Same case passes once the generation evidence is present.
        controller_ok = FakeController()
        result_ok = run_ok(controller_ok, "pointer_movement")
        self.assertEqual(result_ok["overall"], "PASS")
        self.assertEqual(result_ok["stages"]["evidence"]["found"]["evidence_generation"], "epoch-20260919")

    def test_lease_expiry_requires_generation_evidence(self) -> None:
        observation = {key: value for key, value in DEFAULT_OBSERVATION.items() if key != "evidence_generation"}
        controller = FakeController(script={"observe": observation})
        result = run_ok(controller, "lease_expiry")
        self.assertEqual(result["overall"], "BLOCKED")

    def test_stale_hmac_requires_audit_evidence(self) -> None:
        observation = {key: value for key, value in DEFAULT_OBSERVATION.items() if key != "audit_ref"}
        controller = FakeController(script={"observe": observation})
        result = run_ok(controller, "stale_hmac")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertIn("missing_evidence:audit_ref", result["stages"]["evidence"]["detail"])
        controller_ok = FakeController()
        result_ok = run_ok(controller_ok, "stale_hmac")
        self.assertEqual(result_ok["overall"], "PASS")
        self.assertEqual(result_ok["stages"]["evidence"]["found"]["audit_ref"], "audit-op-1")

    def test_unknown_ack_requires_durable_reconcile_proof(self) -> None:
        controller = FakeController(
            script={"reconcile": {"reconciled": True, "proof_ref": "ref-without-proof-flag"}}
        )
        result = run_ok(controller, "unknown_ack")
        self.assertNotEqual(result["overall"], "PASS")
        self.assertIn(
            "missing_evidence:durable_reconcile_proof",
            result["stages"]["evidence"]["detail"],
        )
        controller_ok = FakeController()
        result_ok = run_ok(controller_ok, "unknown_ack")
        self.assertEqual(result_ok["overall"], "PASS")
        self.assertEqual(
            result_ok["stages"]["evidence"]["found"]["durable_reconcile_proof"],
            "fake-reconcile-proof",
        )

    def test_cases_without_extra_evidence_are_skip(self) -> None:
        controller = FakeController()
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["stages"]["evidence"]["status"], "SKIP")
        result = run_ok(controller, "worker_restart")
        self.assertEqual(result["stages"]["evidence"]["status"], "SKIP")

    def test_every_frozen_case_has_a_spec(self) -> None:
        self.assertEqual(
            set(CASE_SPECS),
            set(e4_fault_driver.FAULT_CASES_BY_PROFILE["native-single-node"])
            | set(FAULT_CASES_LEGACY_COMPAT)
            | {"rabbit_transport_unavailable"},
        )


class TimeoutDisconnectTests(unittest.TestCase):
    """Timeouts and disconnects map to UNKNOWN; recovery still runs once."""

    def test_apply_timeout_unknown_recovery_run_no_retry(self) -> None:
        controller = FakeController(script={"apply": ControllerTimeout("cut")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["apply"]["detail"], "controller_timeout")
        self.assertEqual(result["stages"]["observe"]["status"], "SKIP")
        self.assertEqual(controller.call_count("apply"), 1, "exactly one attempt")
        self.assertEqual(controller.call_count("observe"), 0)
        self.assertEqual(controller.call_count("restore"), 1)
        self.assertEqual(controller.call_count("reconcile"), 1)
        self.assertEqual(result["retries"], 0)
        # Default fake reconcile proves durable state, so a future approved
        # attempt would be permitted - but this run never retried.
        self.assertTrue(result["retry_permitted"])

    def test_apply_disconnect_unknown(self) -> None:
        controller = FakeController(script={"apply": ControllerDisconnect("cut")})
        result = run_ok(controller, "worker_restart")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["apply"]["detail"], "controller_disconnect")

    def test_apply_generic_exception_unknown_with_error_class(self) -> None:
        controller = FakeController(script={"apply": ValueError("boom")})
        result = run_ok(controller, "worker_restart")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["apply"]["detail"], "controller_error:ValueError")

    def test_observe_disconnect_unknown_restore_still_runs(self) -> None:
        controller = FakeController(script={"observe": ControllerDisconnect("cut")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["observe"]["detail"], "controller_disconnect")
        self.assertEqual(result["stages"]["cross_check"]["status"], "SKIP")
        self.assertEqual(controller.call_count("restore"), 1)
        self.assertEqual(controller.call_count("reconcile"), 1)

    def test_unknown_without_reconciliation_forbids_retry(self) -> None:
        controller = FakeController(
            script={"apply": ControllerTimeout("cut"), "reconcile": ControllerDisconnect("cut")}
        )
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertFalse(result["retry_permitted"])
        self.assertIn("durable reconciliation", result["retry_requires"])
        self.assertEqual(controller.call_count("apply"), 1, "no automatic replay")

    def test_apply_refusal_blocked_with_recovery(self) -> None:
        controller = FakeController(script={"apply": {"applied": False}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["apply"]["detail"], "apply_refused_by_controller")
        # Durable prepare intent exists, so recovery still runs exactly once.
        self.assertEqual(controller.call_count("restore"), 1)
        self.assertEqual(controller.call_count("reconcile"), 1)

    def test_apply_unproven_without_ref_unknown(self) -> None:
        controller = FakeController(script={"apply": {"applied": True}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["apply"]["detail"], "apply_ref_missing")


class RestoreRecoveryTests(unittest.TestCase):
    """Partial-failure restore, reconciliation and postcondition handling."""

    def test_restore_refused_is_unknown_never_pass(self) -> None:
        controller = FakeController(script={"restore": {"restored": False}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["restore"]["detail"], "restoration_unproven")
        self.assertFalse(result["restoration_proven"])

    def test_restore_exception_is_unknown(self) -> None:
        controller = FakeController(script={"restore": ControllerTimeout("cut")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["restore"]["detail"], "controller_timeout")
        self.assertFalse(result["restoration_proven"])

    def test_reconcile_failure_is_unknown_and_forbids_retry(self) -> None:
        controller = FakeController(script={"reconcile": {"reconciled": False}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["reconcile"]["detail"], "reconciliation_unproven")
        self.assertFalse(result["retry_permitted"])
        self.assertIn("reconcile", result["retry_requires"])

    def test_reconcile_without_proof_ref_unknown(self) -> None:
        controller = FakeController(script={"reconcile": {"reconciled": True}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["reconcile"]["detail"], "reconciliation_proof_ref_missing")

    def test_postcondition_violation_is_fail(self) -> None:
        controller = FakeController(script={"verify_postcondition": {"ok": False, "checks": {"drift": "fault-still-applied"}}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "FAIL")
        self.assertEqual(result["stages"]["postcondition"]["detail"], "postcondition_violation")

    def test_postcondition_exception_is_unknown(self) -> None:
        controller = FakeController(script={"verify_postcondition": RuntimeError("boom")})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["postcondition"]["detail"], "controller_error:RuntimeError")

    def test_postcondition_unproven_is_unknown(self) -> None:
        controller = FakeController(script={"verify_postcondition": {"checks": {}}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["stages"]["postcondition"]["detail"], "postcondition_unproven")


class NoRetryNoReplayTests(unittest.TestCase):
    """MAX_ATTEMPTS == 1 everywhere; reconciliation gates any future attempt."""

    def test_no_hook_runs_twice_on_failing_run(self) -> None:
        controller = FakeController(script={"apply": ControllerTimeout("cut")})
        run_ok(controller, "redis_unavailable")
        for name, _ in controller.calls:
            self.assertEqual(controller.call_count(name), 1, name)

    def test_matrix_with_failures_never_retries(self) -> None:
        script: Dict[str, Any] = {"apply": ControllerTimeout("cut")}
        controller = FakeController(script=script)
        result = run_fault_matrix(controller, make_authorization(), allow_live_execution=True)
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(controller.call_count("apply"), 6, "one attempt per fault, no replay")
        for fault in result["faults"]:
            self.assertEqual(fault["retries"], 0)
            self.assertEqual(fault["attempt"], 1)

    def test_retry_permitted_only_after_proven_reconciliation(self) -> None:
        permitted = run_ok(FakeController(), "redis_unavailable")
        self.assertTrue(permitted["retry_permitted"])
        blocked = run_ok(
            FakeController(script={"reconcile": ControllerDisconnect("cut")}),
            "redis_unavailable",
        )
        self.assertFalse(blocked["retry_permitted"])
        self.assertIn("NEW operation id", blocked["retry_requires"])

    def test_max_attempts_constant(self) -> None:
        self.assertEqual(MAX_ATTEMPTS, 1)
        self.assertEqual(e4_fault_driver.MAX_ATTEMPTS, 1)


class LiveGateAndHygieneTests(unittest.TestCase):
    """Tripwires, plan surface and token hygiene."""

    def test_default_live_gate_blocks_without_controller_contact(self) -> None:
        controller = FakeController()
        result = run_fault_case(controller, make_authorization(), "redis_unavailable")
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["stages"]["live_gate"]["detail"], "allow_live_execution_false")
        self.assertEqual(controller.calls, [])

    def test_matrix_default_live_gate_blocks_without_controller_contact(self) -> None:
        controller = FakeController()
        result = run_fault_matrix(controller, make_authorization())
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(controller.calls, [])
        self.assertEqual(result["integration_claim"], "BLOCKED")

    def test_native_live_execution_is_explicitly_blocked(self) -> None:
        controller = FakeController()
        native_fault = e4_fault_driver.FAULT_CASES_BY_PROFILE["native-single-node"][0]
        result = _run_fault_case(
            controller,
            {
                **make_authorization(fault_ids=[native_fault]),
            },
            native_fault,
            allow_live_execution=True,
            profile="native-single-node",
        )
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(
            result["stages"]["profile_execution"]["detail"],
            "native_fault_controller_not_implemented",
        )
        self.assertEqual(controller.calls, [])

    def test_matrix_without_controller_blocked(self) -> None:
        result = run_fault_matrix(None, make_authorization(), allow_live_execution=True)
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertEqual(result["integration_claim"], "BLOCKED")

    def test_matrix_bad_authorization_blocked_before_contact(self) -> None:
        controller = FakeController()
        result = run_fault_matrix(controller, {"run_id": "!!"}, allow_live_execution=True)
        self.assertEqual(result["overall"], "BLOCKED")
        self.assertIn("invalid:run_id", ";".join(result["authorization_problems"]))
        self.assertEqual(controller.calls, [])

    def test_results_never_contain_authorization_token_values(self) -> None:
        controller = FakeController()
        result = run_fault_matrix(controller, make_authorization(), allow_live_execution=True)
        serialized = json.dumps(result)
        self.assertNotIn(ISOLATE_TOKEN, serialized)
        self.assertNotIn(APPROVAL_TOKEN, serialized)
        self.assertEqual(result["authorization"]["token_values_recorded"], False)

    def test_controller_derived_strings_are_scrubbed_and_bounded(self) -> None:
        leak_ref = "ref at fault-node.example.invalid and https://secret.example.com/x"
        controller = FakeController(script={"prepare": {"prepared": True, "prepare_ref": leak_ref}})
        result = run_ok(controller, "redis_unavailable")
        self.assertEqual(result["overall"], "PASS")
        stored_ref = result["stages"]["prepare"]["prepare_ref"]
        self.assertIn("[redacted-host]", stored_ref)
        self.assertNotIn("fault-node.example.invalid", stored_ref)
        self.assertNotIn("example.com", stored_ref)
        self.assertLessEqual(len(stored_ref), 120)

    def test_plan_marks_every_case_planned_and_integration_blocked(self) -> None:
        plan = build_fault_plan(
            run_id=RUN_ID,
            campaign_id="authz-validation-20260919-single-node-002",
            profile=LEGACY_PROFILE,
        )
        self.assertEqual([case["fault_id"] for case in plan["cases"]], list(FAULT_CASES))
        for case in plan["cases"]:
            self.assertEqual(case["status"], "PLANNED")
        self.assertEqual(plan["live_fault_matrix_integration"]["status"], "BLOCKED")
        self.assertTrue(plan["live_fault_matrix_integration"]["reason"])
        hooks = [hook["hook"] for hook in plan["controller_contract"]["hooks"]]
        self.assertEqual(
            hooks,
            [
                "capabilities",
                "preflight",
                "prepare",
                "apply",
                "observe",
                "restore",
                "reconcile",
                "verify_postcondition",
            ],
        )
        self.assertEqual(
            plan["controller_contract"]["hooks"][0]["returns"],
            "mapping with supported_faults + run-scoped isolation + read_only_preflight",
        )
        self.assertNotIn("controller", plan, "a plan cannot embed a controller instance")

    def test_module_integration_claim_is_blocked(self) -> None:
        self.assertEqual(e4_fault_driver.LIVE_FAULT_MATRIX_INTEGRATION, "BLOCKED")
        self.assertIn("test_control.rs", e4_fault_driver.LIVE_INTEGRATION_REASON)


class CliTests(unittest.TestCase):
    """Default/offline CLI prints the plan and BLOCKED, writes nothing."""

    def _capture_main(self, argv: Optional[List[str]]) -> Tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = e4_fault_driver.main(argv)
        return code, buffer.getvalue()

    def test_default_cli_prints_plan_and_blocked(self) -> None:
        code, output = self._capture_main([])
        self.assertEqual(code, 0)
        self.assertIn("BLOCKED", output)
        self.assertIn("memory_channel_suspect", output)
        self.assertNotIn("redis_unavailable", output)
        plan = json.loads(output[output.index("{"):])
        self.assertEqual(plan["kind"], "e4_fault_plan")
        self.assertEqual(plan["profile"], "native-single-node")
        for case in plan["cases"]:
            self.assertEqual(case["status"], "PLANNED")

    def test_plan_flag_prints_the_same_plan(self) -> None:
        code, output = self._capture_main(["--plan", "--profile", LEGACY_PROFILE])
        self.assertEqual(code, 0)
        self.assertIn("live_fault_matrix_integration", output)
        self.assertIn('"status": "BLOCKED"', output)

    def test_no_execution_flag_exists(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            with self.assertRaises(SystemExit) as caught:
                e4_fault_driver.main(["--run"])
        self.assertEqual(caught.exception.code, 2)

    def test_help_exits_zero_without_executing_anything(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with self.assertRaises(SystemExit) as caught:
                e4_fault_driver.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        output = buffer.getvalue()
        self.assertIn("fault primitive", output)
        self.assertIn("--plan", output)


if __name__ == "__main__":
    unittest.main()
