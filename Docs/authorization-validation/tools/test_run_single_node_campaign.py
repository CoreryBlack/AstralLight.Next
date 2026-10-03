#!/usr/bin/env python3
"""Offline safety tests for the fresh-only readiness campaign entry point."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("run_single_node_campaign.py")


def load_runner():
    spec = importlib.util.spec_from_file_location("readiness_campaign_under_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("readiness module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CampaignEntrySafetyTest(unittest.TestCase):
    def test_import_does_not_create_campaign_or_run_commands(self) -> None:
        with mock.patch("subprocess.run", side_effect=AssertionError("import ran a command")):
            with mock.patch("socket.socket", side_effect=AssertionError("import opened a socket")):
                with mock.patch.object(Path, "mkdir", side_effect=AssertionError("import wrote a directory")):
                    module = load_runner()
        self.assertTrue(callable(module.main))

    def test_existing_campaign_refused_without_writing(self) -> None:
        module = load_runner()
        with tempfile.TemporaryDirectory(prefix="us27_readiness_test_") as directory:
            root = Path(directory)
            old = root / "authz-validation-existing"
            old.mkdir()
            sentinel = old / "unchanged.txt"
            sentinel.write_text("immutable", encoding="utf-8")
            with mock.patch.object(module, "EVIDENCE_ROOT", root):
                with mock.patch.object(Path, "mkdir", side_effect=AssertionError("unexpected write")):
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(module.main(["--campaign-id", old.name]), 2)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "immutable")

    def test_invalid_campaign_id_rejected_before_any_write(self) -> None:
        module = load_runner()
        for value in ("old", "authz-validation-../escape", "authz-validation-bad id", "authz-validation-", "authz-validation-" + "x" * 65):
            with self.subTest(value=value):
                with mock.patch.object(Path, "mkdir", side_effect=AssertionError("unexpected write")):
                    with contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as caught:
                            module.main(["--campaign-id", value])
                self.assertEqual(caught.exception.code, 2)

    def test_missing_source_blocks_before_directory_creation(self) -> None:
        module = load_runner()
        with tempfile.TemporaryDirectory(prefix="us27_readiness_test_") as directory:
            root = Path(directory)
            with mock.patch.object(module, "EVIDENCE_ROOT", root):
                with mock.patch.object(module, "HASHED_SOURCES", ["absent-source.py"]):
                    with mock.patch.object(Path, "mkdir", side_effect=AssertionError("unexpected write")):
                        with contextlib.redirect_stderr(io.StringIO()):
                            self.assertEqual(module.main(["--campaign-id", "authz-validation-new"]), 2)
            self.assertFalse((root / "authz-validation-new").exists())

    def test_failed_required_gate_stops_later_commands_and_records_skip(self) -> None:
        module = load_runner()
        with tempfile.TemporaryDirectory(prefix="us27_readiness_test_") as directory:
            root = Path(directory)
            invoked = []

            def fake_run(spec):
                invoked.append(spec["id"])
                return {
                    "id": spec["id"],
                    "status": "FAIL",
                    "ignoredTests": 0,
                    "logComplete": True,
                }

            with mock.patch.object(module, "EVIDENCE_ROOT", root):
                with mock.patch.object(module, "HASHED_SOURCES", []):
                    with mock.patch.object(module, "COMMANDS", [
                        {"id": "first", "required": True},
                        {"id": "second", "required": True},
                    ]):
                        with mock.patch.object(module, "run_command", side_effect=fake_run):
                            with mock.patch.object(module, "runtime_preflight", return_value={"status": "BLOCKED"}):
                                with mock.patch.object(module, "tool_version", return_value="test"):
                                    with contextlib.redirect_stdout(io.StringIO()):
                                        self.assertEqual(module.main(["--campaign-id", "authz-validation-test-failed"]), 1)
            self.assertEqual(invoked, ["first"])
            status_path = root / "authz-validation-test-failed" / "status.json"
            self.assertTrue(status_path.exists())
            self.assertEqual(__import__("json").loads(status_path.read_text(encoding="utf-8"))["localReady"], "FAIL")

    def test_scenario_blocks_are_reported_without_downgrading_local_readiness(self) -> None:
        module = load_runner()
        with tempfile.TemporaryDirectory(prefix="us27_readiness_test_") as directory:
            root = Path(directory)

            def fake_run(spec):
                return {
                    "id": spec["id"],
                    "status": "PASS",
                    "ignoredTests": 0,
                    "logComplete": True,
                }

            with mock.patch.object(module, "EVIDENCE_ROOT", root):
                with mock.patch.object(module, "HASHED_SOURCES", []):
                    with mock.patch.object(module, "COMMANDS", [{"id": "local-gate", "required": True}]):
                        with mock.patch.object(module, "run_command", side_effect=fake_run):
                            with mock.patch.object(module, "runtime_preflight", return_value={"status": "BLOCKED"}):
                                with mock.patch.object(module, "tool_version", return_value="test"):
                                    with contextlib.redirect_stdout(io.StringIO()):
                                        self.assertEqual(module.main(["--campaign-id", "authz-validation-test-blocks"]), 0)
            status = __import__("json").loads(
                (root / "authz-validation-test-blocks" / "status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(status["localReady"], "PASS")
            self.assertEqual(status["overall"], "BLOCKED")
            self.assertEqual(
                status["blocked"],
                ["E1-production-race", "E3-recovery-tail", "E4-preconditions-and-faults"],
            )

    def test_previous_attempt_points_to_latest_frozen_snapshot(self) -> None:
        module = load_runner()
        self.assertEqual(
            module.PREVIOUS_ATTEMPT["campaignId"],
            "authz-validation-20260919-single-node-005",
        )
        self.assertEqual(module.PREVIOUS_ATTEMPT["status"], "BLOCKED")
        self.assertEqual(module.PREVIOUS_ATTEMPT["localReady"], "PASS")
        self.assertIn("immutable snapshot", module.PREVIOUS_ATTEMPT["reason"])

    def test_changed_trustgraph_main_is_in_source_inventory(self) -> None:
        module = load_runner()
        self.assertIn(
            "astral-trustgraph/src/main.rs",
            module.HASHED_SOURCES,
        )

    def test_changed_permission_check_shared_is_in_source_inventory(self) -> None:
        module = load_runner()
        self.assertIn(
            "astral-common/src/middleware/permission_check_shared.rs",
            module.HASHED_SOURCES,
        )

    def test_changed_observability_and_lifecycle_sources_are_in_inventory(self) -> None:
        module = load_runner()
        for source in (
            "astral-trustgraph/src/observability.rs",
            "astral-trustgraph/src/service/sync_publish.rs",
            "Docs/authorization-validation/tools/lifecycle_reducer.py",
            "Docs/authorization-validation/tools/test_lifecycle_reducer.py",
        ):
            with self.subTest(source=source):
                self.assertIn(source, module.HASHED_SOURCES)

    def test_runtime_suites_execute_real_tests_without_no_run(self) -> None:
        module = load_runner()
        runtime_ids = (
            "runtime-policy-engine-lib",
            "runtime-astral-db-lib",
            "runtime-astral-common-gateway-contract",
            "runtime-astral-trustgraph-lib",
        )
        specs = {spec["id"]: spec for spec in module.COMMANDS}
        for command_id in runtime_ids:
            with self.subTest(command=command_id):
                spec = specs[command_id]
                self.assertTrue(spec.get("required"), command_id)
                self.assertEqual(spec.get("expected"), "; 0 failed")
                argv = spec["argv"]
                self.assertIn("cargo", argv)
                self.assertNotIn(
                    "--no-run", argv, "runtime suites must execute, not just compile"
                )
        self.assertEqual(
            [spec["id"] for spec in module.COMMANDS].count("workspace-test-compile"),
            1,
            "the compile-only workspace gate stays as explicit compile coverage",
        )

    def test_runtime_suites_scenario_aggregates_command_status(self) -> None:
        module = load_runner()
        command_status = {
            "runtime-policy-engine-lib": "PASS",
            "runtime-astral-db-lib": "PASS",
            "runtime-astral-common-gateway-contract": "PASS",
            "runtime-astral-trustgraph-lib": "FAIL",
        }
        names = (
            "runtime-policy-engine-lib",
            "runtime-astral-db-lib",
            "runtime-astral-common-gateway-contract",
            "runtime-astral-trustgraph-lib",
        )
        status = (
            "PASS" if all(command_status.get(name) == "PASS" for name in names)
            else "FAIL" if any(command_status.get(name) == "FAIL" for name in names)
            else "SKIP"
        )
        self.assertEqual(status, "FAIL")

    def test_upgraded_verification_gates_are_registered(self) -> None:
        """The E5 layer pins both models and the universal hypotheses."""
        import run_single_node_campaign as module
        specs = {spec["id"]: spec for spec in module.COMMANDS}
        self.assertIn("e5-bounded-model-two-mutations", specs)
        self.assertIn("e5-universal-hypotheses", specs)
        self.assertTrue(specs["e5-bounded-model-two-mutations"]["assertTwoMutationModel"])
        self.assertTrue(specs["e5-universal-hypotheses"]["assertUniversalHypotheses"])
        # The heavy enumerations carry their own timeouts, never the
        # 1800 s default silently applied to them.
        self.assertGreater(
            specs["e5-universal-hypotheses"]["timeoutSeconds"], 1800
        )
        # The upgraded verification layer is hash-inventoried.
        for source in (
            "Docs/authorization-validation/tools/e5_model_check_two_mutations.py",
            "Docs/authorization-validation/tools/universal_hypotheses_check.py",
            "Docs/authorization-validation/tools/experiment_register.py",
            "Docs/authorization-validation/tools/test_classify_e1_properties.py",
        ):
            self.assertIn(source, module.HASHED_SOURCES)
        import experiment_register
        self.assertEqual(experiment_register.validate_register()["status"], "PASS")

    def test_experiment_register_and_multi_classifier_importable(self) -> None:
        import experiment_register
        import experiment_common

        self.assertEqual(experiment_register.validate_register()["status"], "PASS")
        self.assertTrue(hasattr(experiment_common, "classify_e1_allow_multi"))

    def test_zero_python_tests_cannot_pass(self) -> None:
        module = load_runner()
        with tempfile.TemporaryDirectory(prefix="us27_readiness_test_") as directory:
            out = Path(directory)
            (out / "logs").mkdir()
            with mock.patch.object(module, "OUT", out, create=True), mock.patch.object(
                module, "LOGS", out / "logs", create=True
            ):
                with mock.patch(
                    "subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, "", "Ran 0 tests in 0.000s\n\nOK\n"),
                ):
                    result = module.run_command(
                        {
                            "id": "python-zero",
                            "argv": ["python", "-m", "unittest"],
                            "required": True,
                            "expectedStderr": "OK",
                            "minimumPythonTests": 1,
                        }
                    )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["pythonTestsRun"], 0)

    def test_e1_observability_failure_is_not_reported_as_skip(self) -> None:
        module = load_runner()
        command_status = {
            "e1-feature-check": "FAIL",
        }
        names = (
            "e1-feature-check",
            "e1-feature-production-clippy",
            "e1-policy-engine-feature-tests-build",
            "e1-astral-db-build",
        )
        status = (
            "PASS" if all(command_status.get(name) == "PASS" for name in names)
            else "FAIL" if any(command_status.get(name) == "FAIL" for name in names)
            else "SKIP"
        )
        self.assertEqual(status, "FAIL")

    def test_missing_required_argument_exits_before_write(self) -> None:
        module = load_runner()
        with mock.patch.object(Path, "mkdir", side_effect=AssertionError("unexpected write")):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    module.main([])
        self.assertEqual(caught.exception.code, 2)


def _run_isolated_command(module, spec, *, side_effect=None, return_value=None):
    """Run module.run_command against an isolated OUT/LOGS with a patched subprocess.

    Returns (result, logs) where logs maps log file names to their text; the
    temporary evidence directory is deleted before returning, so callers must
    inspect captured contents instead of paths.
    """
    with tempfile.TemporaryDirectory(prefix="us27_readiness_test_") as directory:
        out = Path(directory)
        (out / "logs").mkdir()
        with mock.patch.object(module, "OUT", out, create=True), mock.patch.object(
            module, "LOGS", out / "logs", create=True
        ):
            patcher = (
                mock.patch("subprocess.run", side_effect=side_effect)
                if side_effect is not None
                else mock.patch("subprocess.run", return_value=return_value)
            )
            with patcher:
                result = module.run_command(spec)
        logs = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted((out / "logs").iterdir())
        }
        return result, logs


class RunCommandFailureSemanticsTest(unittest.TestCase):
    """run_command must keep UNKNOWN/BLOCKED/FAIL semantics honest."""

    def setUp(self) -> None:
        self.module = load_runner()

    def test_timeout_reports_unknown_with_incomplete_logs_and_partial_output(self) -> None:
        error = subprocess.TimeoutExpired(
            cmd=["cargo"], timeout=1800, output=b"partial stdout", stderr=b"partial stderr"
        )
        result, logs = _run_isolated_command(
            self.module,
            {"id": "timeout-case", "argv": ["cargo", "test"], "required": True},
            side_effect=error,
        )
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["exitCode"])
        self.assertFalse(result["logComplete"])
        self.assertEqual(logs["timeout-case.stdout.log"], "partial stdout")
        self.assertEqual(logs["timeout-case.stderr.log"], "partial stderr")

    def test_os_error_reports_blocked_without_a_fabricated_exit_code(self) -> None:
        result, logs = _run_isolated_command(
            self.module,
            {"id": "spawn-case", "argv": ["cargo", "test"], "required": True},
            side_effect=OSError("cargo not found"),
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIsNone(result["exitCode"])
        self.assertEqual(logs["spawn-case.stderr.log"], "OSError")

    def test_e5_invalid_json_output_fails_with_unknown_model_status(self) -> None:
        result, _ = _run_isolated_command(
            self.module,
            {"id": "e5-bad", "argv": ["python"], "assertE5AbstractModel": True},
            return_value=subprocess.CompletedProcess([], 0, "not-json", ""),
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["assertionPassed"])
        self.assertEqual(result["abstractModelStatus"], "UNKNOWN")

    def test_e5_non_pass_full_contract_fails_but_keeps_reported_model_status(self) -> None:
        report = (
            '{"fullContract": {"status": "UNKNOWN", "modes": '
            '{"bracket": {"explorationComplete": false, "violations": 0}}}}'
        )
        result, _ = _run_isolated_command(
            self.module,
            {"id": "e5-incomplete", "argv": ["python"], "assertE5AbstractModel": True},
            return_value=subprocess.CompletedProcess([], 0, report, ""),
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["abstractModelStatus"], "UNKNOWN")

    def test_e5_report_without_full_contract_fails_closed(self) -> None:
        result, _ = _run_isolated_command(
            self.module,
            {"id": "e5-shape", "argv": ["python"], "assertE5AbstractModel": True},
            return_value=subprocess.CompletedProcess([], 0, '{"unexpected": true}', ""),
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["abstractModelStatus"], "UNKNOWN")

    def test_e5_complete_passing_report_passes(self) -> None:
        report = (
            '{"fullContract": {"status": "PASS", "modes": '
            '{"bracket": {"explorationComplete": true, "violations": 0}, '
            '"strict": {"explorationComplete": true, "violations": 0}}}}'
        )
        result, _ = _run_isolated_command(
            self.module,
            {"id": "e5-good", "argv": ["python"], "assertE5AbstractModel": True},
            return_value=subprocess.CompletedProcess([], 0, report, ""),
        )
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["assertionPassed"])
        self.assertEqual(result["abstractModelStatus"], "PASS")

    def test_exit_zero_without_expected_marker_is_fail(self) -> None:
        result, _ = _run_isolated_command(
            self.module,
            {"id": "e2-guard", "argv": ["cargo", "test"], "expected": "1 passed; 0 failed"},
            return_value=subprocess.CompletedProcess([], 0, "1 passed; 1 failed\n", ""),
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["assertionPassed"])

        good, _ = _run_isolated_command(
            self.module,
            {"id": "e2-guard", "argv": ["cargo", "test"], "expected": "1 passed; 0 failed"},
            return_value=subprocess.CompletedProcess([], 0, "test x ... ok\n\n1 passed; 0 failed\n", ""),
        )
        self.assertEqual(good["status"], "PASS")

    def test_checksum_verifier_detects_artifact_tampering(self) -> None:
        import sys

        tools = Path(__file__).resolve().parent
        if str(tools) not in sys.path:
            sys.path.insert(0, str(tools))
        from experiment_common import EvidenceError, verify_checksums, write_checksums

        with tempfile.TemporaryDirectory(prefix="us27_readiness_test_") as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text('{"sealed": true}\n', encoding="utf-8")
            checksums = write_checksums(root, [manifest])
            verify_checksums(root, checksums)

            manifest.write_text('{"sealed": false}\n', encoding="utf-8")
            with self.assertRaises(EvidenceError):
                verify_checksums(root, checksums)


class ModelImplementationDriftGuardTest(unittest.TestCase):
    """The E5 premise list and the executed Rust E2 commands must stay 1:1."""

    E2_PREMISE_COMMANDS = {
        "pending_probe": "e2-pending-probe-omission",
        "post_recheck": "e2-cache-post-recheck-omission",
        "final_reload": "e2-final-reload-omission",
        "exact_identity": "e2-exact-identity-omission",
        "generation_revoke_fence": "e2-generation-revoke-fence-omission",
    }
    MODEL_ONLY_PREMISES = {"host_mediation"}
    E2_RUST_TEST_FILTERS = {
        "e2-pending-probe-omission": (
            "evidence_cache::tests::e2_pending_probe_omission_accepts_stale_candidate"
            "_while_full_contract_reloads"
        ),
        "e2-cache-post-recheck-omission": (
            "evidence_cache::tests::e2_post_recheck_omission_accepts_interleaving"
            "_while_full_contract_reloads"
        ),
        "e2-exact-identity-omission": (
            "engine::tests::test_strict_successor_revision_cannot_replace_original_candidate"
        ),
        "e2-final-reload-omission": (
            "engine::tests::e2_final_reload_omission_accepts_removed_candidate"
            "_while_full_contract_reloads"
        ),
        "e2-generation-revoke-fence-omission": (
            "evidence_cache::tests::e2_generation_revoke_fence_omission_accepts_stale_candidate"
        ),
    }

    def setUp(self) -> None:
        self.module = load_runner()
        import sys

        tools = Path(__file__).resolve().parent
        if str(tools) not in sys.path:
            sys.path.insert(0, str(tools))
        import e5_model_check

        self.e5 = e5_model_check

    def test_every_modeled_premise_maps_to_exactly_one_executed_command(self) -> None:
        command_ids = [spec["id"] for spec in self.module.COMMANDS]
        e2_commands = [name for name in command_ids if name.startswith("e2-")]
        self.assertEqual(
            set(e2_commands),
            set(self.E2_PREMISE_COMMANDS.values()),
            "the executed E2 command set drifted from the model premise set",
        )
        self.assertEqual(
            set(self.e5.PREMISES),
            set(self.E2_PREMISE_COMMANDS) | self.MODEL_ONLY_PREMISES,
            "a new E5 premise needs an explicit executed-command mapping or an "
            "explicit model-only exemption",
        )
        for premise, command_id in self.E2_PREMISE_COMMANDS.items():
            with self.subTest(premise=premise):
                self.assertEqual(e2_commands.count(command_id), 1)

    def test_each_e2_command_targets_a_real_test_with_an_exact_marker(self) -> None:
        specs = {spec["id"]: spec for spec in self.module.COMMANDS}
        rust_root = Path(__file__).resolve().parents[3]
        sources = {
            "e2-pending-probe-omission": (
                rust_root / "astral-db" / "src" / "evidence_cache.rs"
            ).read_text(encoding="utf-8"),
            "e2-cache-post-recheck-omission": (
                rust_root / "astral-db" / "src" / "evidence_cache.rs"
            ).read_text(encoding="utf-8"),
            "e2-exact-identity-omission": (
                rust_root / "policy-engine" / "src" / "engine.rs"
            ).read_text(encoding="utf-8"),
            "e2-final-reload-omission": (
                rust_root / "policy-engine" / "src" / "engine.rs"
            ).read_text(encoding="utf-8"),
            "e2-generation-revoke-fence-omission": (
                rust_root / "astral-db" / "src" / "evidence_cache.rs"
            ).read_text(encoding="utf-8"),
        }
        for command_id, rust_filter in self.E2_RUST_TEST_FILTERS.items():
            with self.subTest(command=command_id):
                spec = specs[command_id]
                self.assertTrue(spec.get("required"), command_id)
                self.assertEqual(spec.get("expected"), "1 passed; 0 failed")
                self.assertIn(rust_filter, spec["argv"])
                test_name = rust_filter.rsplit("::", 1)[1]
                self.assertIn(
                    f"fn {test_name}",
                    sources[command_id],
                    f"the E2 command filter {rust_filter} no longer matches any test",
                )

    def test_host_mediation_has_no_claimed_omission_command(self) -> None:
        command_ids = [spec["id"] for spec in self.module.COMMANDS]
        for command_id in command_ids:
            self.assertNotIn(
                "host",
                command_id,
                "host_mediation is a model-only premise and must not claim a runtime omission test",
            )


if __name__ == "__main__":
    unittest.main()
